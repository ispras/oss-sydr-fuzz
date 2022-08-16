// Copyright 2022 ISP RAS
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//###############################################################################

#include <stdio.h>

#include <rz_core.h>
#include "rz_bin.h"
#include "rz_util/rz_buf.h"

RzCore *g_rz_core;

extern int LLVMFuzzerInitialize(int *argc, char ***argv) {
	g_rz_core = rz_core_new();
	return 0;
}

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	RzBuffer *buff = rz_buf_new_with_bytes((const ut8 *)Data, (ut64)Size);
	RzBin *bin = rz_bin_new();

	RzBinOptions opts = { 0 };
	opts.filename = "<internal>";
	opts.obj_opts.patch_relocs = true;

	RzBinFile *bf = rz_bin_open_buf(bin, buff, &opts);
	if (!bf) {
		rz_bin_free(bin);
		return 0;
	};

	RzBinDwarfDebugAbbrev *da = rz_bin_dwarf_parse_abbrev(bf);
	RzBinDwarfDebugInfo *info = da ? rz_bin_dwarf_parse_info(bf, da) : NULL;
	HtUP *loc_table = rz_bin_dwarf_parse_loc(bf, g_rz_core->analysis->bits / 8);
	if (info) {
		RzAnalysisDwarfContext ctx = {
			.info = info,
			.loc = loc_table
		};
		rz_analysis_dwarf_process_info(g_rz_core->analysis, &ctx);
	}
	if (loc_table) {
		rz_bin_dwarf_loc_free(loc_table);
	}
	RzBinDwarfLineInfo *li = rz_bin_dwarf_parse_line(bf, info, RZ_BIN_DWARF_LINE_INFO_MASK_LINES);

	rz_bin_dwarf_line_info_free(li);
	rz_bin_dwarf_debug_info_free(info);
	rz_bin_dwarf_debug_abbrev_free(da);
	rz_buf_free(buff);
	rz_bin_free(bin);

	return 0;
}
