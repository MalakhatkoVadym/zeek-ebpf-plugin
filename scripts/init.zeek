module SocketFilter;

export {
    ## Size of the ring-buffer.
    const buffer_size = 128 * 1024 * 1024 &redef;
	## Size of an individual block. Needs to be a multiple of page size.
	const block_size = 4096 * 8 &redef;
	## Retire timeout for a single block.
	const block_timeout = 10msec &redef;
}
