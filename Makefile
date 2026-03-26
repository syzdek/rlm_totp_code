#
#   TOTP Code Module for FreeRADIUS
#   Copyright (C) 2026 David M. Syzdek <david@syzdek.net>.
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are
#   met:
#
#      1. Redistributions of source code must retain the above copyright
#         notice, this list of conditions and the following disclaimer.
#
#      2. Redistributions in binary form must reproduce the above copyright
#         notice, this list of conditions and the following disclaimer in the
#         documentation and/or other materials provided with the distribution.
#
#      3. Neither the name of the copyright holder nor the names of its
#         contributors may be used to endorse or promote products derived from
#         this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
#   IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
#   THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
#   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
#   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
#   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
#   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
#   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
#   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
#   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
#   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

FREERADIUS_SOURCE			?= freeradius-server

MOD_DOC					:= $(FREERADIUS_SOURCE)/doc/modules/totp_code
MOD_CONFIG				:= $(FREERADIUS_SOURCE)/raddb/mods-available/totp_code
SITE_CONFIG				:= $(FREERADIUS_SOURCE)/raddb/sites-available/totp_code
ALL_MK					:= $(FREERADIUS_SOURCE)/src/modules/rlm_totp_code/all.mk
MOD_SOURCE				:= $(FREERADIUS_SOURCE)/src/modules/rlm_totp_code/rlm_totp_code.c


.PHONY: all prepare clean

all:
	@echo " "
	@echo "   To copy the rlm_totp_code module into the FreeRADIUS server"
	@echo "   source code, run the following:"
	@echo " "
	@echo "       make FREERADIUS_SOURCE=../freeradius-server-x.x.x prepare"
	@echo " "

prepare:  $(MOD_DOC) $(MOD_CONFIG) $(SITE_CONFIG) $(ALL_MK) $(MOD_SOURCE)

clean:
	rm -f $(MOD_DOC) $(MOD_CONFIG) $(SITE_CONFIG) $(ALL_MK) $(MOD_SOURCE)
	rm -Rf $(FREERADIUS_SOURCE)/src/modules/rlm_totp_code

$(MOD_DOC): README.md
	cp README.md $(@)

$(MOD_CONFIG): totp_code.mods-available
	cp totp_code.mods-available $(@)

$(SITE_CONFIG): totp_code.sites-available
	cp totp_code.sites-available $(@)

$(MOD_SOURCE): rlm_totp_code.c
	@test -d $(FREERADIUS_SOURCE)/src/modules/rlm_totp_code || \
		mkdir $(FREERADIUS_SOURCE)/src/modules/rlm_totp_code
	cp rlm_totp_code.c $(@)

$(ALL_MK): all.mk $(MOD_SOURCE)
	cp all.mk $(@)


# end of Makefile
