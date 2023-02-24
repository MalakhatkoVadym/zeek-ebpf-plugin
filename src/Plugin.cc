/** 
 * Copyright (c) 2018 by Iwan Timmer
 * 
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "Plugin.h"
#include "SocketFilter.h"
#include "iosource/Component.h"


namespace plugin::SF { Plugin plugin; }

using namespace plugin::SF;

zeek::plugin::Configuration Plugin::Configure() {
	AddComponent(new zeek::iosource::PktSrcComponent("SFReader", "sf", zeek::iosource::PktSrcComponent::LIVE, ::iosource::pktsrc::SFSource::InstantiateSF));

	zeek::plugin::Configuration config;
	config.name = "malakhatkovadym::sf";
	config.description = "Packet acquisition via SF";
	config.version.major = 0;
	config.version.minor = 1;
	return config;
}
