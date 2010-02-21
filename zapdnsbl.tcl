#
# zapdnsbl.tcl  Version: 0.1-dev  Author: Stefan Wold <ratler@stderr.eu>
###
#
#
###
# LICENSE:
# Copyright (C) 2010  Stefan Wold <ratler@stderr.eu>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# ZAP DNS Blacklist

if {[namespace exists ::zapbl]} {namespace delete ::zapbl}
namespace eval ::zapbl {

}


# ---- Only edit stuff below this line if you know what you are doing ----

# Channel flags


# Bindings
