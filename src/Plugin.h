/** 
 * Copyright (c) 2018 by Iwan Timmer
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef ZEEK_PLUGIN_ITIMMER_SF
#define ZEEK_PLUGIN_ITIMMER_SF

#include <plugin/Plugin.h>

namespace plugin {
namespace SF {

class Plugin : public zeek::plugin::Plugin {
protected:
	// Overridden from plugin::Plugin.
	zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
