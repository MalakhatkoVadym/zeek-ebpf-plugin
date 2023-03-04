/**
 * Copyright (c) 2018 by Iwan Timmer
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "zeek-config.h"
#include "SocketFilter.h"
#include <bpf/bpf.h>

#include "bpf_insn.h"
#include <net/if.h>
#include <sf.bif.h>
#include <string>

#ifndef TP_STATUS_CSUM_VALID
#define TP_STATUS_CSUM_VALID (1 << 7)
#endif

extern "C"
{
#include <libelf.h>
#include <gelf.h>
#include <linux/perf_event.h>
#include "perf-sys.h"
#include <sys/ioctl.h>

#define DEBUGFS "/sys/kernel/debug/tracing/"

	typedef void (*fixup_map_cb)(struct bpf_map_data *map, int idx);
#define MAX_PROGS 32
#define MAX_MAPS 32

	struct bpf_load_map_def
	{
		unsigned int type;
		unsigned int key_size;
		unsigned int value_size;
		unsigned int max_entries;
		unsigned int map_flags;
		unsigned int inner_map_idx;
		unsigned int numa_node;
	};

	struct bpf_map_data
	{
		int fd;
		char *name;
		size_t elf_offset;
		struct bpf_load_map_def def;
	};

	struct bpf_map_data map_data[MAX_MAPS];
	int prog_fd[MAX_PROGS];
	int map_fd[MAX_MAPS];
	int event_fd[MAX_PROGS];

	char bpf_log_buf[BPF_LOG_BUF_SIZE];

	int prog_cnt;
	int prog_array_fd = -1;
	int map_data_count = 0;

	static char license[128];
	static bool processed_sec[128];

	static int kern_version;

	static int populate_prog_array(const char *event, int prog_fd)
	{
		int ind = atoi(event), err;

		err = bpf_map_update_elem(prog_array_fd, &ind, &prog_fd, BPF_ANY);
		if (err < 0)
		{
			printf("failed to store prog_fd in prog_array\n");
			return -1;
		}
		return 0;
	}

	static int parse_relo_and_apply(Elf_Data *data, Elf_Data *symbols,
									GElf_Shdr *shdr, struct bpf_insn *insn,
									struct bpf_map_data *maps, int nr_maps)
	{
		int i, nrels;

		nrels = shdr->sh_size / shdr->sh_entsize;

		for (i = 0; i < nrels; i++)
		{
			GElf_Sym sym;
			GElf_Rel rel;
			unsigned int insn_idx;
			bool match = false;
			int map_idx;

			gelf_getrel(data, i, &rel);

			insn_idx = rel.r_offset / sizeof(struct bpf_insn);

			gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym);

			if (insn[insn_idx].code != (BPF_LD | BPF_IMM | BPF_DW))
			{
				printf("invalid relo for insn[%d].code 0x%x\n",
					   insn_idx, insn[insn_idx].code);
				return 1;
			}
			insn[insn_idx].src_reg = BPF_PSEUDO_MAP_FD;

			/* Match FD relocation against recorded map_data[] offset */
			for (map_idx = 0; map_idx < nr_maps; map_idx++)
			{
				if (maps[map_idx].elf_offset == sym.st_value)
				{
					match = true;
					break;
				}
			}
			if (match)
			{
				insn[insn_idx].imm = maps[map_idx].fd;
			}
			else
			{
				printf("invalid relo for insn[%d] no map_data match\n",
					   insn_idx);
				return 1;
			}
		}

		return 0;
	}

	static int load_maps(struct bpf_map_data *maps, int nr_maps,
						 fixup_map_cb fixup_map)
	{
		int i, numa_node;

		for (i = 0; i < nr_maps; i++)
		{
			if (fixup_map)
			{
				fixup_map(&maps[i], i);
				/* Allow userspace to assign map FD prior to creation */
				if (maps[i].fd != -1)
				{
					map_fd[i] = maps[i].fd;
					continue;
				}
			}

			numa_node = maps[i].def.map_flags & BPF_F_NUMA_NODE ? maps[i].def.numa_node : -1;

			if (maps[i].def.type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
				maps[i].def.type == BPF_MAP_TYPE_HASH_OF_MAPS)
			{
				int inner_map_fd = map_fd[maps[i].def.inner_map_idx];

				map_fd[i] = bpf_create_map_in_map_node((bpf_map_type)maps[i].def.type,
													   maps[i].name,
													   maps[i].def.key_size,
													   inner_map_fd,
													   maps[i].def.max_entries,
													   maps[i].def.map_flags,
													   numa_node);
			}
			else
			{
				map_fd[i] = bpf_create_map_node((bpf_map_type)maps[i].def.type,
												maps[i].name,
												maps[i].def.key_size,
												maps[i].def.value_size,
												maps[i].def.max_entries,
												maps[i].def.map_flags,
												numa_node);
			}
			if (map_fd[i] < 0)
			{
				printf("failed to create a map: %d %s\n",
					   errno, strerror(errno));
				return 1;
			}
			maps[i].fd = map_fd[i];

			if (maps[i].def.type == BPF_MAP_TYPE_PROG_ARRAY)
				prog_array_fd = map_fd[i];
		}
		return 0;
	}

	static int cmp_symbols(const void *l, const void *r)
	{
		const GElf_Sym *lsym = (const GElf_Sym *)l;
		const GElf_Sym *rsym = (const GElf_Sym *)r;

		if (lsym->st_value < rsym->st_value)
			return -1;
		else if (lsym->st_value > rsym->st_value)
			return 1;
		else
			return 0;
	}

	static int load_elf_maps_section(struct bpf_map_data *maps, int maps_shndx,
									 Elf *elf, Elf_Data *symbols, int strtabidx)
	{
		int map_sz_elf, map_sz_copy;
		bool validate_zero = false;
		Elf_Data *data_maps;
		int i, nr_maps;
		GElf_Sym *sym;
		Elf_Scn *scn;
		// int copy_sz;

		if (maps_shndx < 0)
			return -EINVAL;
		if (!symbols)
			return -EINVAL;

		/* Get data for maps section via elf index */
		scn = elf_getscn(elf, maps_shndx);
		if (scn)
			data_maps = elf_getdata(scn, NULL);
		if (!scn || !data_maps)
		{
			printf("Failed to get Elf_Data from maps section %d\n",
				   maps_shndx);
			return -EINVAL;
		}

		/* For each map get corrosponding symbol table entry */
		sym = (GElf_Sym *)calloc(MAX_MAPS + 1, sizeof(GElf_Sym));
		for (i = 0, nr_maps = 0; i < symbols->d_size / sizeof(GElf_Sym); i++)
		{
			assert(nr_maps < MAX_MAPS + 1);
			if (!gelf_getsym(symbols, i, &sym[nr_maps]))
				continue;
			if (sym[nr_maps].st_shndx != maps_shndx)
				continue;
			/* Only increment iif maps section */
			nr_maps++;
		}

		/* Align to map_fd[] order, via sort on offset in sym.st_value */
		qsort(sym, nr_maps, sizeof(GElf_Sym), cmp_symbols);

		/* Keeping compatible with ELF maps section changes
		 * ------------------------------------------------
		 * The program size of struct bpf_load_map_def is known by loader
		 * code, but struct stored in ELF file can be different.
		 *
		 * Unfortunately sym[i].st_size is zero.  To calculate the
		 * struct size stored in the ELF file, assume all struct have
		 * the same size, and simply divide with number of map
		 * symbols.
		 */
		map_sz_elf = data_maps->d_size / nr_maps;
		map_sz_copy = sizeof(struct bpf_load_map_def);
		if (map_sz_elf < map_sz_copy)
		{
			/*
			 * Backward compat, loading older ELF file with
			 * smaller struct, keeping remaining bytes zero.
			 */
			map_sz_copy = map_sz_elf;
		}
		else if (map_sz_elf > map_sz_copy)
		{
			/*
			 * Forward compat, loading newer ELF file with larger
			 * struct with unknown features. Assume zero means
			 * feature not used.  Thus, validate rest of struct
			 * data is zero.
			 */
			validate_zero = true;
		}

		/* Memcpy relevant part of ELF maps data to loader maps */
		for (i = 0; i < nr_maps; i++)
		{
			struct bpf_load_map_def *def;
			unsigned char *addr, *end;
			const char *map_name;
			size_t offset;

			map_name = elf_strptr(elf, strtabidx, sym[i].st_name);
			maps[i].name = strdup(map_name);
			if (!maps[i].name)
			{
				printf("strdup(%s): %s(%d)\n", map_name,
					   strerror(errno), errno);
				free(sym);
				return -errno;
			}

			/* Symbol value is offset into ELF maps section data area */
			offset = sym[i].st_value;
			def = (struct bpf_load_map_def *)(data_maps->d_buf + offset);
			maps[i].elf_offset = offset;
			memset(&maps[i].def, 0, sizeof(struct bpf_load_map_def));
			memcpy(&maps[i].def, def, map_sz_copy);

			/* Verify no newer features were requested */
			if (validate_zero)
			{
				addr = (unsigned char *)def + map_sz_copy;
				end = (unsigned char *)def + map_sz_elf;
				for (; addr < end; addr++)
				{
					if (*addr != 0)
					{
						free(sym);
						return -EFBIG;
					}
				}
			}
		}

		free(sym);
		return nr_maps;
	}

	static int get_sec(Elf *elf, int i, GElf_Ehdr *ehdr, char **shname,
					   GElf_Shdr *shdr, Elf_Data **data)
	{
		Elf_Scn *scn;

		scn = elf_getscn(elf, i);
		if (!scn)
			return 1;

		if (gelf_getshdr(scn, shdr) != shdr)
			return 2;

		*shname = elf_strptr(elf, ehdr->e_shstrndx, shdr->sh_name);
		if (!*shname || !shdr->sh_size)
			return 3;

		*data = elf_getdata(scn, 0);
		if (!*data || elf_getdata(scn, *data) != NULL)
			return 4;

		return 0;
	}

	static int load_and_attach(const char *event, struct bpf_insn *prog, int size)
	{
		bool is_socket = strncmp(event, "socket", 6) == 0;
		bool is_kprobe = strncmp(event, "kprobe/", 7) == 0;
		bool is_kretprobe = strncmp(event, "kretprobe/", 10) == 0;
		bool is_tracepoint = strncmp(event, "tracepoint/", 11) == 0;
		bool is_raw_tracepoint = strncmp(event, "raw_tracepoint/", 15) == 0;
		bool is_xdp = strncmp(event, "xdp", 3) == 0;
		bool is_perf_event = strncmp(event, "perf_event", 10) == 0;
		bool is_cgroup_skb = strncmp(event, "cgroup/skb", 10) == 0;
		bool is_cgroup_sk = strncmp(event, "cgroup/sock", 11) == 0;
		bool is_sockops = strncmp(event, "sockops", 7) == 0;
		bool is_sk_skb = strncmp(event, "sk_skb", 6) == 0;
		bool is_sk_msg = strncmp(event, "sk_msg", 6) == 0;
		size_t insns_cnt = size / sizeof(struct bpf_insn);
		enum bpf_prog_type prog_type;
		char buf[256];
		int fd, efd, err, id;
		struct perf_event_attr attr = {};

		attr.type = PERF_TYPE_TRACEPOINT;
		attr.sample_type = PERF_SAMPLE_RAW;
		attr.sample_period = 1;
		attr.wakeup_events = 1;

		if (is_socket)
		{
			prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
		}
		else if (is_kprobe || is_kretprobe)
		{
			prog_type = BPF_PROG_TYPE_KPROBE;
		}
		else if (is_tracepoint)
		{
			prog_type = BPF_PROG_TYPE_TRACEPOINT;
		}
		else if (is_raw_tracepoint)
		{
			prog_type = BPF_PROG_TYPE_RAW_TRACEPOINT;
		}
		else if (is_xdp)
		{
			prog_type = BPF_PROG_TYPE_XDP;
		}
		else if (is_perf_event)
		{
			prog_type = BPF_PROG_TYPE_PERF_EVENT;
		}
		else if (is_cgroup_skb)
		{
			prog_type = BPF_PROG_TYPE_CGROUP_SKB;
		}
		else if (is_cgroup_sk)
		{
			prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
		}
		else if (is_sockops)
		{
			prog_type = BPF_PROG_TYPE_SOCK_OPS;
		}
		else if (is_sk_skb)
		{
			prog_type = BPF_PROG_TYPE_SK_SKB;
		}
		else if (is_sk_msg)
		{
			prog_type = BPF_PROG_TYPE_SK_MSG;
		}
		else
		{
			printf("Unknown event '%s'\n", event);
			return -1;
		}

		fd = bpf_load_program(prog_type, prog, insns_cnt, license, kern_version,
							  bpf_log_buf, BPF_LOG_BUF_SIZE);
		if (fd < 0)
		{
			printf("bpf_load_program() err=%d\n%s", errno, bpf_log_buf);
			return -1;
		}

		prog_fd[prog_cnt++] = fd;

		if (is_xdp || is_perf_event || is_cgroup_skb || is_cgroup_sk)
			return 0;

		if (is_socket || is_sockops || is_sk_skb || is_sk_msg)
		{
			if (is_socket)
				event += 6;
			else
				event += 7;
			if (*event != '/')
				return 0;
			event++;
			if (!isdigit(*event))
			{
				printf("invalid prog number\n");
				return -1;
			}
			return populate_prog_array(event, fd);
		}

		if (is_raw_tracepoint)
		{
			efd = bpf_raw_tracepoint_open(event + 15, fd);
			if (efd < 0)
			{
				printf("tracepoint %s %s\n", event + 15, strerror(errno));
				return -1;
			}
			event_fd[prog_cnt - 1] = efd;
			return 0;
		}

		if (is_kprobe || is_kretprobe)
		{
			bool need_normal_check = true;
			const char *event_prefix = "";

			if (is_kprobe)
				event += 7;
			else
				event += 10;

			if (*event == 0)
			{
				printf("event name cannot be empty\n");
				return -1;
			}

			if (isdigit(*event))
				return populate_prog_array(event, fd);

#ifdef __x86_64__
			if (strncmp(event, "sys_", 4) == 0)
			{
				snprintf(buf, sizeof(buf),
						 "echo '%c:__x64_%s __x64_%s' >> /sys/kernel/debug/tracing/kprobe_events",
						 is_kprobe ? 'p' : 'r', event, event);
				err = system(buf);
				if (err >= 0)
				{
					need_normal_check = false;
					event_prefix = "__x64_";
				}
			}
#endif
			if (need_normal_check)
			{
				snprintf(buf, sizeof(buf),
						 "echo '%c:%s %s' >> /sys/kernel/debug/tracing/kprobe_events",
						 is_kprobe ? 'p' : 'r', event, event);
				err = system(buf);
				if (err < 0)
				{
					printf("failed to create kprobe '%s' error '%s'\n",
						   event, strerror(errno));
					return -1;
				}
			}

			strcpy(buf, DEBUGFS);
			strcat(buf, "events/kprobes/");
			strcat(buf, event_prefix);
			strcat(buf, event);
			strcat(buf, "/id");
		}
		else if (is_tracepoint)
		{
			event += 11;

			if (*event == 0)
			{
				printf("event name cannot be empty\n");
				return -1;
			}
			strcpy(buf, DEBUGFS);
			strcat(buf, "events/");
			strcat(buf, event);
			strcat(buf, "/id");
		}

		efd = open(buf, O_RDONLY, 0);
		if (efd < 0)
		{
			printf("failed to open event %s\n", event);
			return -1;
		}

		err = read(efd, buf, sizeof(buf));
		if (err < 0 || err >= sizeof(buf))
		{
			printf("read from '%s' failed '%s'\n", event, strerror(errno));
			return -1;
		}

		close(efd);

		buf[err] = 0;
		id = atoi(buf);
		attr.config = id;

		efd = sys_perf_event_open(&attr, -1 /*pid*/, 0 /*cpu*/, -1 /*group_fd*/, 0);
		if (efd < 0)
		{
			printf("event %d fd %d err %s\n", id, efd, strerror(errno));
			return -1;
		}
		event_fd[prog_cnt - 1] = efd;
		err = ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
		if (err < 0)
		{
			printf("ioctl PERF_EVENT_IOC_ENABLE failed err %s\n",
				   strerror(errno));
			return -1;
		}
		err = ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);
		if (err < 0)
		{
			printf("ioctl PERF_EVENT_IOC_SET_BPF failed err %s\n",
				   strerror(errno));
			return -1;
		}

		return 0;
	}

	static int do_load_bpf_file(const char *path, fixup_map_cb fixup_map)
	{
		int fd, i, ret, maps_shndx = -1, strtabidx = -1;
		Elf *elf;
		GElf_Ehdr ehdr;
		GElf_Shdr shdr, shdr_prog;
		Elf_Data *data, *data_prog, *data_maps = NULL, *symbols = NULL;
		char *shname, *shname_prog;
		int nr_maps = 0;

		/* reset global variables */
		kern_version = 0;
		memset(license, 0, sizeof(license));
		memset(processed_sec, 0, sizeof(processed_sec));

		if (elf_version(EV_CURRENT) == EV_NONE)
			return 1;

		fd = open(path, O_RDONLY, 0);
		if (fd < 0)
			return 1;

		elf = elf_begin(fd, ELF_C_READ, NULL);

		if (!elf)
			return 1;

		if (gelf_getehdr(elf, &ehdr) != &ehdr)
			return 1;

		/* clear all kprobes */
		i = system("echo \"\" > /sys/kernel/debug/tracing/kprobe_events");

		/* scan over all elf sections to get license and map info */
		for (i = 1; i < ehdr.e_shnum; i++)
		{

			if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
				continue;

			if (0) /* helpful for llvm debugging */
				printf("section %d:%s data %p size %zd link %d flags %d\n",
					   i, shname, data->d_buf, data->d_size,
					   shdr.sh_link, (int)shdr.sh_flags);

			if (strcmp(shname, "license") == 0)
			{
				processed_sec[i] = true;
				memcpy(license, data->d_buf, data->d_size);
			}
			else if (strcmp(shname, "version") == 0)
			{
				processed_sec[i] = true;
				if (data->d_size != sizeof(int))
				{
					printf("invalid size of version section %zd\n",
						   data->d_size);
					return 1;
				}
				memcpy(&kern_version, data->d_buf, sizeof(int));
			}
			else if (strcmp(shname, "maps") == 0)
			{
				int j;

				maps_shndx = i;
				data_maps = data;
				for (j = 0; j < MAX_MAPS; j++)
					map_data[j].fd = -1;
			}
			else if (shdr.sh_type == SHT_SYMTAB)
			{
				strtabidx = shdr.sh_link;
				symbols = data;
			}
		}

		ret = 1;

		if (!symbols)
		{
			printf("missing SHT_SYMTAB section\n");
			goto done;
		}

		if (data_maps)
		{
			nr_maps = load_elf_maps_section(map_data, maps_shndx,
											elf, symbols, strtabidx);
			if (nr_maps < 0)
			{
				printf("Error: Failed loading ELF maps (errno:%d):%s\n",
					   nr_maps, strerror(-nr_maps));
				goto done;
			}
			if (load_maps(map_data, nr_maps, fixup_map))
				goto done;
			map_data_count = nr_maps;

			processed_sec[maps_shndx] = true;
		}

		/* process all relo sections, and rewrite bpf insns for maps */
		for (i = 1; i < ehdr.e_shnum; i++)
		{
			if (processed_sec[i])
				continue;

			if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
				continue;

			if (shdr.sh_type == SHT_REL)
			{
				struct bpf_insn *insns;

				/* locate prog sec that need map fixup (relocations) */
				if (get_sec(elf, shdr.sh_info, &ehdr, &shname_prog,
							&shdr_prog, &data_prog))
					continue;

				if (shdr_prog.sh_type != SHT_PROGBITS ||
					!(shdr_prog.sh_flags & SHF_EXECINSTR))
					continue;

				insns = (struct bpf_insn *)data_prog->d_buf;
				processed_sec[i] = true; /* relo section */

				if (parse_relo_and_apply(data, symbols, &shdr, insns,
										 map_data, nr_maps))
					continue;
			}
		}

		/* load programs */
		for (i = 1; i < ehdr.e_shnum; i++)
		{

			if (processed_sec[i])
				continue;

			if (get_sec(elf, i, &ehdr, &shname, &shdr, &data))
				continue;

			if (memcmp(shname, "kprobe/", 7) == 0 ||
				memcmp(shname, "kretprobe/", 10) == 0 ||
				memcmp(shname, "tracepoint/", 11) == 0 ||
				memcmp(shname, "raw_tracepoint/", 15) == 0 ||
				memcmp(shname, "xdp", 3) == 0 ||
				memcmp(shname, "perf_event", 10) == 0 ||
				memcmp(shname, "socket", 6) == 0 ||
				memcmp(shname, "cgroup/", 7) == 0 ||
				memcmp(shname, "sockops", 7) == 0 ||
				memcmp(shname, "sk_skb", 6) == 0 ||
				memcmp(shname, "sk_msg", 6) == 0)
			{
				ret = load_and_attach(shname, (bpf_insn *)data->d_buf,
									  data->d_size);
				if (ret != 0)
					goto done;
			}
		}

	done:
		close(fd);
		return ret;
	}
}

#define DEFAULT_COMPLETION_RING_SIZE 32
#define DEFAULT_FILL_RING_SIZE 1024
#define DEFAULT_RX_RING_SIZE 1024
#define NUM_FRAMES 2048
#define FRAME_SIZE 2048

using namespace iosource::pktsrc;

SFSource::~SFSource()
{
	Close();
}

SFSource::SFSource(const std::string &path, bool is_live)
{
	if (!is_live)
		Error("Socket Filter source does not support offline input");

	props.path = path;
	props.is_live = is_live;
}

inline bool SFSource::BindInterface()
{
	struct ifreq ifr;
	struct sockaddr_ll saddr_ll;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", props.path.c_str());

	ret = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (ret < 0)
		return false;

	memset(&saddr_ll, 0, sizeof(saddr_ll));
	saddr_ll.sll_family = AF_PACKET;
	saddr_ll.sll_protocol = htons(ETH_P_ALL);
	saddr_ll.sll_ifindex = ifr.ifr_ifindex;

	ret = bind(fd, (struct sockaddr *)&saddr_ll, sizeof(saddr_ll));
	return (ret >= 0);
}

inline bool SFSource::EnablePromiscMode()
{
	struct ifreq ifr;
	struct packet_mreq mreq;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", props.path.c_str());

	ret = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (ret < 0)
		return false;

	memset(&mreq, 0, sizeof(mreq));
	mreq.mr_ifindex = ifr.ifr_ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;

	ret = setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	return (ret >= 0);
}

inline uint32_t SFSource::GetFanoutMode(bool defrag)
{
	uint32_t fanout_mode;

	switch (zeek::BifConst::SocketFilter::fanout_mode->AsEnum())
	{
	case BifEnum::SocketFilter::FANOUT_CPU:
		fanout_mode = PACKET_FANOUT_CPU;
		break;
#ifdef PACKET_FANOUT_QM
	case BifEnum::SocketFilter::FANOUT_QM:
		fanout_mode = PACKET_FANOUT_QM;
		break;
#endif
#ifdef PACKET_FANOUT_CBPF
	case BifEnum::SocketFilter::FANOUT_CBPF:
		fanout_mode = PACKET_FANOUT_CBPF;
		break;
#endif
#ifdef PACKET_FANOUT_EBPF
	case BifEnum::SocketFilter::FANOUT_EBPF:
		fanout_mode = PACKET_FANOUT_EBPF;
		break;
#endif
	default:
		fanout_mode = PACKET_FANOUT_HASH;
		break;
	}

	if (defrag)
		fanout_mode |= PACKET_FANOUT_FLAG_DEFRAG;

	return fanout_mode;
}

inline bool SFSource::ConfigureFanoutGroup(bool enabled, bool defrag)
{
	if (enabled)
	{
		uint32_t fanout_arg, fanout_id;
		int ret;

		fanout_id = zeek::BifConst::SocketFilter::fanout_id;
		fanout_arg = ((fanout_id & 0xffff) | (GetFanoutMode(defrag) << 16));

		ret = setsockopt(fd, SOL_PACKET, PACKET_FANOUT,
						 &fanout_arg, sizeof(fanout_arg));

		if (ret < 0)
			return false;
	}
	return true;
}

void SFSource::Open()
{

	uint64_t buffer_size = zeek::BifConst::SocketFilter::buffer_size;
	uint64_t block_size = zeek::BifConst::SocketFilter::block_size;
	int block_timeout_msec = static_cast<int>(zeek::BifConst::SocketFilter::block_timeout * 1000.0);
	int link_type = zeek::BifConst::SocketFilter::link_type;
	bool enable_fanout = zeek::BifConst::SocketFilter::enable_fanout;
	bool enable_defrag = zeek::BifConst::SocketFilter::enable_defrag;
	bool enable_hw_timestamping = zeek::BifConst::SocketFilter::enable_hw_timestamping;
	// bool enable_fanout = zeek::BifConst::SocketFilter::enable_fanout;
	// bool enable_defrag = zeek::BifConst::SocketFilter::enable_defrag;
	char filename[256];
	snprintf(filename, sizeof(filename), "filter.o");
	if (do_load_bpf_file(filename, NULL))
	{
		Error("Error");
		Error(bpf_log_buf);
	}
	fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	// struct sockaddr_ll sll;
	// memset(&sll, 0, sizeof(sll));
	// sll.sll_family = AF_PACKET;
	// sll.sll_ifindex = if_nametoindex(props.path.c_str());
	// sll.sll_protocol = htons(ETH_P_ALL);
	// if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
	// 	printf("bind to %s: %s\n", props.path.c_str(), strerror(errno));
	// 	close(fd);
	// 	return;
	// }

	if (fd < 0)
	{
		Error(errno ? strerror(errno) : "unable to create socket");
		return;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_BPF, prog_fd,
				   sizeof(prog_fd[0])) < 0)
	{
		Error(errno ? strerror(errno) : "setsockopt error");
	}

	try
	{
		sf_ring = new SF_Ring(fd, buffer_size, block_size, block_timeout_msec);
	}
	catch (SF_RingException &e)
	{
		Error(errno ? strerror(errno) : "unable to create RX-ring");
		close(fd);
		return;
	}

	if (!BindInterface())
	{
		Error(errno ? strerror(errno) : "unable to bind to interface");
		close(fd);
		return;
	}

	if (!EnablePromiscMode())
	{
		Error(errno ? strerror(errno) : "unable enter promiscious mode");
		close(fd);
		return;
	}
	if (!ConfigureFanoutGroup(enable_fanout, enable_defrag))
	{
		Error(errno ? strerror(errno) : "failed to join fanout group");
		close(fd);
		return;
	}

	if (!ConfigureHWTimestamping(enable_hw_timestamping))
	{
		Error(errno ? strerror(errno) : "failed to configure hardware timestamping");
		close(fd);
		return;
	}

	stats = {};

	props.netmask = NETMASK_UNKNOWN;
	props.is_live = true;
	props.link_type = link_type;

	stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
	num_discarded = 0;

	Opened(props);
}

inline bool SFSource::ConfigureHWTimestamping(bool enabled)
{
	if (enabled)
	{
		struct ifreq ifr;
		struct hwtstamp_config hwts_cfg;
		int ret, opt;

		memset(&hwts_cfg, 0, sizeof(hwts_cfg));
		hwts_cfg.tx_type = HWTSTAMP_TX_OFF;
		hwts_cfg.rx_filter = HWTSTAMP_FILTER_ALL;
		memset(&ifr, 0, sizeof(ifr));
		snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", props.path.c_str());
		ifr.ifr_data = (char *)&hwts_cfg;

		ret = ioctl(fd, SIOCSHWTSTAMP, &ifr);
		if (ret < 0)
			return false;

		opt = SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE;
		ret = setsockopt(fd, SOL_PACKET, PACKET_TIMESTAMP,
						 &opt, sizeof(opt));
		if (ret < 0)
			return false;
	}
	return true;
}

void SFSource::Close()
{
	if (fd)
	{
		close(fd);
		fd = 0;
	}

	Closed();
}

bool SFSource::ExtractNextPacket(zeek::Packet *pkt)
{
	if (!fd)
		return false;

	// struct iphdr *ip_header;
	// size_t bytes;
	// while((bytes = recv(fd, ring_buffer[index], 16383, 0)) < 0) {
	// size_t undefined = -1;
	// if (bytes == undefined)
	// {
	// 	return false;
	// }

	// struct timeval ts;
	// gettimeofday(&ts, NULL);

	// ip_header = (struct iphdr*)(ring_buffer[index] + sizeof(struct ethhdr));
	// int len = ntohs(ip_header->tot_len);

	// pkt->Init(props.link_type, &ts, bytes, len, ring_buffer[index]);

	// index++;
	// stats.received++;
	// stats.bytes_received += bytes;

	// return true;
	// }

	if (!fd)
		return false;

	struct tpacket3_hdr *packet = 0;
	const u_char *data;

	if (!sf_ring->GetNextPacket(&packet))
	{
		stats.dropped++;
		return false;
	}

	current_hdr.ts.tv_sec = packet->tp_sec;
	current_hdr.ts.tv_usec = packet->tp_nsec / 1000;
	current_hdr.caplen = packet->tp_snaplen;
	current_hdr.len = packet->tp_len;
	data = (u_char *)packet + packet->tp_mac;

	// if ( !ApplyBPFFilter(current_filter, &current_hdr, data) )
	// 	{
	// 	++num_discarded;
	// 	DoneWithPacket();
	// 	continue;
	// 	}

	pkt->Init(props.link_type, &current_hdr.ts, current_hdr.caplen, current_hdr.len, data);

	if (packet->tp_status & TP_STATUS_VLAN_VALID)
		pkt->vlan = packet->hv1.tp_vlan_tci;

#if ZEEK_VERSION_NUMBER >= 50100
	switch (checksum_mode)
	{
	case BifEnum::SocketFilter::CHECKSUM_OFF:
	{
		// If set to off, just accept whatever checksum in the packet is correct and
		// skip checking it here and in Zeek.
		pkt->l4_checksummed = true;
		break;
	}
	case BifEnum::SocketFilter::CHECKSUM_KERNEL:
	{
		// If set to kernel, check whether the kernel thinks the checksum is valid. If it
		// does, tell Zeek to skip checking by itself.
		if (((packet->tp_status & TP_STATUS_CSUM_VALID) != 0) ||
			((packet->tp_status & TP_STATUS_CSUMNOTREADY) != 0))
			pkt->l4_checksummed = true;
		else
			pkt->l4_checksummed = false;
		break;
	}
	case BifEnum::SocketFilter::CHECKSUM_ON:
	default:
	{
		// Let Zeek handle it.
		pkt->l4_checksummed = false;
		break;
	}
	}
#endif

	if (current_hdr.len == 0 || current_hdr.caplen == 0)
	{
		Weird("empty_af_packet_header", pkt);
		// stats.dropped++;
		return false;
	}

	stats.received++;
	stats.bytes_received += current_hdr.len;
	return true;

	// stats.dropped++;
	// return false;
}

void SFSource::DoneWithPacket()
{
	sf_ring->ReleasePacket();
}

bool SFSource::PrecompileFilter(int index, const std::string &filter)
{
	return true;
}

bool SFSource::SetFilter(int index)
{
	return true;
}

void SFSource::Statistics(Stats *s)
{
	/*struct xdp_statistics xdp_stats;

	socklen_t opt_length = sizeof(xdp_stats);

	if (getsockopt(fd, SOL_XDP, XDP_STATISTICS, &xdp_stats, &opt_length) < 0)
	{
		Error(errno ? strerror(errno) : "unable to retrieve statistics");
		return;
	}

	stats.dropped = xdp_stats.rx_dropped;
	stats.link = stats.received + stats.dropped;

	s = stats;*/
	memcpy(s, &stats, sizeof(Stats));
}

zeek::iosource::PktSrc *SFSource::InstantiateSF(const std::string &path, bool is_live)
{
	return new SFSource(path, is_live);
}
