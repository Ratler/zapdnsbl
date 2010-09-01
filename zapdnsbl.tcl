#
# zapdnsbl.tcl  Version: 0.1-dev  Author: Stefan Wold <ratler@stderr.eu>
###
# Require / Dependencies
# tcllib >= 1.10 (http://www.tcl.tk/software/tcllib/)
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
    # Path to configuration file
    variable inifile "scripts/zapdnsbl/zapdnsbl.ini"

    # Set console output flag, for debug purpose (default d, ie .console +d)
    variable conflag d
}


# ---- Only edit stuff below this line if you know what you are doing ----

# Channel flags
setudef flag zapbl

# Packages
package require inifile
package require dns

# Bindings
bind join - *!*@* ::zapbl::onJoin
bind dcc -|- zapblcheck ::zapbl::dccCheck
bind dcc -|- help ::stderreu::help


namespace eval ::zapbl {
    # Global variables
    variable version "0.1-dev"
    variable name "zapdnsbl"
    variable longName "ZAP DNS Blacklist"

    variable blacklists
    variable ini

    # Parse INI file
    if {[file exists $::zapbl::inifile]} {
        # Open ini file in read-write mode for easy updating
        set ::zapbl::ini [::ini::open $::zapbl::inifile r+]
        foreach section [::ini::sections $::zapbl::ini] {
            if {[regexp {^bl\:} $section]} {
                putloglev $::zapbl::conflag * "$::zapbl::name - DEBUG: Loading blacklist '$section'"
                lappend ::blacklists [lindex [split $section ":"] end]
            } elseif {[string equal config $section]} {
                putloglev $::zapbl::conflag * "$::zapbl::name - DEBUG: Loading $::zapbl::name '$section'"
            }
        }
    }

    ###
    # Functions
    ###
    proc onJoin { nick host handle channel } {
        # Lower case channel
        set channel [string tolower $channel]

        # Only run if channel is defined
        if {![channel get $channel zapbl]} { return 1 }

        # Exclude ops, voice, friends
        if {[matchattr $handle fov|fov $channel]} {
            putloglev $::zapbl::conflag * "$::zapbl::name: $nick is on exempt list"
            return 1
        }
    }

    # testHost - .zapblcheck <host>
    proc dccCheck { nick idx host } {
        if {[llength [split $host]] != 1} {
            ::zapbl::help $nick $idx zapblcheck; return 0
        }

        set host [string tolower $host]

        # Check if numeric host
        if {[regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $host]} {
            ::zapbl::dnsCheckDnsbl $host $host
            #putidx $idx "$::zapbl::name - TEST: Host was NOT found in any of the blacklists"
        } else {
            set ip [::zapbl::dnsQuery $host resolve]
            putlog "-- IP: $ip"
            if {[regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
                ::zapbl::dnsCheckDnsbl $ip $host
            } else {
                putlog "-- Something went wrong: $ip"
            }
        }
    }

    proc dnsCheckDnsbl { ip host } {
        # Reverse the IP
        regexp {([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})} $ip -> oct1 oct2 oct3 oct4
        set reverseIp "$oct4.$oct3.$oct2.$oct1"

        foreach bl [::ini::sections $::zapbl::ini] {
            if {[regexp {^bl\:} $bl]} {
                set dnsbl [lindex [split $bl ":"] end]
                set address [::zapbl::dnsQuery $reverseIp.$dnsbl dnsbl]
                if {[regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $address]} {
                    set reason [::zapbl::getDnsblReason $bl $address]
                    set template [list %reason% $reason \
                                       %ip% $host]
                    set banreason [::zapbl::template [::zapbl::getBanReason $bl] $template]
                    putlog "$::zapbl::name - TEST: Host '$ip ($host)' was found in $dnsbl reason: $reason"
                    putlog "$::zapbl::name - TEST: Ban message for '$host': $banreason"
                    return 1
                }
            }
        }
    }

    proc dnsQuery { host mode } {
        putlog "-- $host"
        set result [::dns::resolve $host]
        switch -- [::dns::status $result] {
            ok {
                set address [::dns::address $result]
                ::dns::cleanup $result
                return $address
            }
            error {
                set error [::dns::error $result]
                ::dns::cleanup $result
                if {$mode == "resolve"} {
                    return $error
                } elseif {$mode == "dnsbl" && [string match "domain does not exist" $error]} {
                    return ""
                }
                return $error
            }
            timeout {
                putlog "timeout"
            }
            eof {
                putlog "eof"
            }
        }
    }

    # This function will replace %keywords% with supplied substitutes
    proc template { text subs } {
        foreach {arg1 arg2} $subs {
            regsub -all -- $arg1 $text $arg2 text
        }
        return $text
    }

    ###
    # Getters
    ###

    # Getter to retrieve a reason from the ini file
    proc getDnsblReason { bl address } {
        # Last octet in $address is the reason matched against reply:X
        set lastOctet [lindex [split $address "."] end]
        if {[::ini::exists $::zapbl::ini $bl reply:$lastOctet]} {
            set reason [::ini::value $::zapbl::ini $bl reply:$lastOctet]
            return $reason
        }
        return "Unknown"
    }

    # Getter to retrieve a ban reason
    proc getBanReason { bl } {
        if {[::ini::exists $::zapbl::ini $bl ban_message]} {
            return [::ini::value $::zapbl::ini $bl ban_message]
        } elseif {[::ini::exists $::zapbl::ini $bl default_ban_message]} {
            return [::ini::value $::zapbl::ini $bl default_ban_message]
        }
        return ""
    }
}

namespace eval ::stderreu {
    variable helpfuncs

    if {![info exists ::stderreu::helpfuncs] || ![dict exists $::stderreu::helpfuncs zapdnsbl]} {
        dict set ::stderreu::helpfuncs zapdnsbl [list zapdnsbl zapblcheck]
    }

    proc zapdnsbl { idx } {
        putidx $idx "\n\n\002$::zapbl::longName v$::zapbl::version\002 by Ratler"
        ::stderreu::zapblcheck $idx
    }

    proc zapblcheck { idx } {
        putidx $idx "### \002zapblcheck <host>"
    }

    proc zapdnsbldefault { idx } {
        putidx $idx "\n\n\002$::zapbl::longName v$::zapbl::version\002 commands:"
        putidx $idx "   \002zapblcheck"
    }

    proc help { hand idx arg } {
        set myarg [join $arg]
        # First we test if arg is all to print eggdrop builtin commands,
        # then we call the help proc for each script loaded
        if {$myarg == "all"} {
            *dcc:help $hand $idx [join $arg]
            foreach key [dict keys $::stderreu::helpfuncs] {
                ::stderreu::$key $idx
            }
            return 1
        } else {
            foreach key [dict keys $::stderreu::helpfuncs] {
                foreach helpf [dict get $::stderreu::helpfuncs $key] {
                    if { $helpf == $myarg } {
                        ::stderreu::$helpf $idx
                        return 1
                    }
                }
            }
        }

        *dcc:help $hand $idx $myarg

        if {[llength [split $arg]] == 0} {
            foreach key [dict keys $::stderreu::helpfuncs] {
                ::stderreu::${key}default $idx
            }
        }
        return 1
    }
}


putlog "\002$::zapbl::longName v$::zapbl::version\002 by Ratler loaded"
