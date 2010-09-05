#
# zapdnsbl.tcl  Version: 0.2-dev  Author: Stefan Wold <ratler@stderr.eu>
###
# Info:
# ZAP DNS Blacklist is a script that take the host of a user joining
# a channel and check it against configured DNS blacklists (RBL). The
# configuration file is very similar to the format of BOPM.
###
# Require / Dependencies
# tcl >= 8.5
# tcllib >= 1.10 (http://www.tcl.tk/software/tcllib/)
###
# Installation:
# Copy zapdnsbl.tcl and zapdnsbl.ini to your_eggdrop/scripts/zapdnsbl/ then
# add source scripts/zapdnsbl/zapdnsbl.tcl in your eggdrop.conf.
# Reload (rehash) or restart your bot, that is it.
###
# Usage:
# chanset <channel> <+/->zapdnsbl
# This will either enable (+) or disable (-) the script for the
# specified channel
#
# chanset <channel> zapdnsbl.bantime <integer>
# For how long should the ban be active in minutes, if unset the
# script default to 120 minutes
#
# chanset <channel> <+/->zapdnsbl.pubcmd
# Enable (+) or disable (-) public commands (!zapblcheck <host>)
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

if {[namespace exists ::zapdnsbl]} {namespace delete ::zapdnsbl}
namespace eval ::zapdnsbl {
    # Path to configuration file
    variable inifile "scripts/zapdnsbl/zapdnsbl.ini"

    # Set console output flag, for debug purpose (default d, ie .console +d)
    variable conflag d
}


# ---- Only edit stuff below this line if you know what you are doing ----

# Channel flags
setudef flag zapdnsbl
setudef flag zapdnsbl.pubcmd
setudef int zapdnsbl.bantime

# Packages
package require Tcl 8.5
package require inifile
package require dns

# Bindings
bind evnt - prerehash ::zapdnsbl::onEvent
bind join - * ::zapdnsbl::onJoin
bind dcc - zapblcheck ::zapdnsbl::dccCheckDnsbl
bind dcc - help ::stderreu::help
bind pub - !zapblcheck ::zapdnsbl::pubCheckDnsbl

namespace eval ::zapdnsbl {
    # Global variables
    variable version "0.2-dev"
    variable name "zapdnsbl"
    variable longName "ZAP DNS Blacklist"

    variable blacklists
    variable ini

    # Print debug
    proc debug { text } {
        putloglev $::zapdnsbl::conflag * "$::zapdnsbl::name - DEBUG: $text"
    }

    # Parse INI file
    if {[file exists $::zapdnsbl::inifile]} {
        # Open ini file in read-write mode for easy updating
        set ::zapdnsbl::ini [::ini::open $::zapdnsbl::inifile r+]
        foreach section [::ini::sections $::zapdnsbl::ini] {
            if {[regexp {^bl\:} $section]} {
                ::zapdnsbl::debug "Loading blacklist '$section'"
                lappend ::blacklists [lindex [split $section ":"] end]
            } elseif {[string equal config $section]} {
                ::zapdnsbl::debug "Loading $::zapdnsbl::name '$section'"
            }
        }
    }

    ###
    # Functions
    ###
    # onEvent: Used to watch certain events to act upon
    proc onEvent { type } {
        switch -- $type {
            prerehash {
                # Close ini file on rehash
                ::zapdnsbl::debug "Prehash event triggered"
                ::ini::close $::zapdnsbl::ini
            }
        }
    }

    proc onJoin { nick host handle channel } {
        # Lower case channel
        set channel [string tolower $channel]

        # Only run if channel is defined
        if {![channel get $channel zapdnsbl]} { return 1 }

        # Exclude ops, voice, friends
        if {[matchattr $handle fov|fov $channel]} {
            putlog  "$::zapdnsbl::name - $nick is on exempt list"
            return 1
        }

        regexp ".+@(.+)" $host mathces iphost
        set iphost [string tolower $iphost]

        # Check if it is a numeric host or resolve it
        if {![regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $iphost]} {
            set ip [::zapdnsbl::dnsQuery $iphost resolve]
            if {![regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
                putlog "$::zapdnsbl::name - Couldn't resolve '$iphost'. No further action taken."

                # Abort if we fail to resolve the host
                return 0
            }
        } else {
            set ip $iphost
        }

        # Do the DNSBL black magic
        set dnsblData [::zapdnsbl::dnsCheckDnsbl $ip $iphost]

        if {[dict get $dnsblData status] == "FOUND" } {
            # Check if unknown is enabled or abort
            if {![::zapdnsbl::isBanUnknownEnabled "bl:[dict get $dnsblData blacklist]"] && [dict get $dnsblData reason] == "Unknown"} {
                ::zapdnsbl::debug "Host '$nick!$host ([dict get $dnsblData ip])' found in [dict get $dnsblData blacklist] reason '[dict get $dnsblData reason]', will not ban because ban_unknown is set to false"
                return 1
            }
            putlog  "$::zapdnsbl::name - Host '$nick!$host ([dict get $dnsblData ip])' found in [dict get $dnsblData blacklist] reason '[dict get $dnsblData reason]' on channel '$channel', banning with reason '[dict get $dnsblData banreason]'!"
            set bantime [channel get $channel zapdnsbl.bantime]
            if {$bantime == 0} {
                putlog "$::zapdnsbl::name - Bantime not set, defaulting to 120 minutes, set with .chanset #channel zapdnsbl.bantime <integer>."
                set bantime 120
            }

            newchanban $channel "*!*@[dict get $dnsblData host]" $::zapdnsbl::name [dict get $dnsblData banreason] $bantime
            return 1
        }
        ::zapdnsbl::debug "Host '$nick!$host' was not found in any blacklist, status [dict get $dnsblData status] - [dict get $dnsblData ip] - channel $channel"
    }

    # Public channel command to check if host appear in a DNS blacklist
    proc pubCheckDnsbl { nick host handle channel arg } {
        if {![channel get $channel zapdnsbl.pubcmd]} { return 0 }
        if {![regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $arg]} {
            set ip [::zapdnsbl::dnsQuery $arg resolve]
            if {![regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
                putlog "$::zapdnsbl::name - Couldn't resolve '$host'. No further action taken."

                # Abort if we fail to resolve the host
                return 0
            }
        } else {
            set ip $arg
        }

        # Do the DNSBL black magic
        set dnsblData [::zapdnsbl::dnsCheckDnsbl $ip $arg]

        if {[dict get $dnsblData status] == "FOUND"} {
            puthelp "PRIVMSG $channel :$nick: $::zapdnsbl::name - Host '[dict get $dnsblData ip] ([dict get $dnsblData host])' found in [dict get $dnsblData blacklist] reason '[dict get $dnsblData reason]'"
        } else {
            puthelp "PRIVMSG $channel :$nick: $::zapdnsbl::name - Host '[dict get $dnsblData host]' is OK"
        }
    }

    # testHost - .zapblcheck <host>
    proc dccCheckDnsbl { nick idx host } {
        if {[llength [split $host]] != 1} {
            ::stderreu::zapblcheck $idx; return 0
        }

        set host [string tolower $host]

        # Check if it is a numeric host
        if {![regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $host]} {
            set ip [::zapdnsbl::dnsQuery $host resolve]
            ::zapdnsbl::debug " -- IP is $ip"
            if {![regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
                putlog "$::zapdnsbl::name - Couldn't resolve '$host'. No further action taken."

                # Abort if we fail to resolve the host
                return 0
            }
        } else {
            set ip $host
        }

        set dnsblData [::zapdnsbl::dnsCheckDnsbl $ip $host]

        if {[dict get $dnsblData status] == "FOUND"} {
            putlog "$::zapdnsbl::name - TEST: Host '[dict get $dnsblData ip] ([dict get $dnsblData host])' was found in [dict get $dnsblData blacklist] reason: [dict get $dnsblData reason]"
            putlog "$::zapdnsbl::name - TEST: Ban message for '[dict get $dnsblData host]': [dict get $dnsblData banreason]"
        } else {
            putlog "$::zapdnsbl::name - TEST: Host '[dict get $dnsblData ip] ([dict get $dnsblData host])' was NOT found in any blacklist, status [dict get $dnsblData status]"
        }
    }

    proc dnsCheckDnsbl { ip host } {
        # Reverse the IP
        regexp {([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})} $ip -> oct1 oct2 oct3 oct4
        set reverseIp "$oct4.$oct3.$oct2.$oct1"

        # Default dnsbl stuff
        dict set dnsblData status "OK"
        dict set dnsblData ip $ip
        dict set dnsblData host $host

        foreach bl [::ini::sections $::zapdnsbl::ini] {
            ::zapdnsbl::debug "Trying blacklist $bl..."
            if {[regexp {^bl\:} $bl]} {
                set dnsbl [lindex [split $bl ":"] end]
                set address [::zapdnsbl::dnsQuery $reverseIp.$dnsbl dnsbl]
                if {[regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} [lindex $address 0]]} {
                    dict set dnsblData status "FOUND"

                    foreach ipAdd $address {
                        lappend reason [::zapdnsbl::getDnsblReason $bl $ipAdd]
                    }
                    set reason [join $reason ", "]
                    set template [list %reason% $reason \
                                       %ip% $host]
                    dict set dnsblData reason $reason
                    dict set dnsblData banreason [::zapdnsbl::template [::zapdnsbl::getBanReason $bl] $template]
                    dict set dnsblData blacklist $dnsbl

                    return $dnsblData
                }
            }
        }
        return $dnsblData
    }

    proc dnsQuery { host mode } {
        set result [::dns::resolve $host]
        switch -- [::dns::status $result] {
            ok {
                # Just pick the first entry if a list is returned
                set address [::dns::address $result]
                ::zapdnsbl::debug "Address $address"
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
                putlog "$::zapdnsbl::name - dnsQuery() timeout"
                return ""
            }
            eof {
                putlog "$::zapdnsbl::name - dnsQuery() eof"
                return ""
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
        if {[::ini::exists $::zapdnsbl::ini $bl reply:$lastOctet]} {
            set reason [::ini::value $::zapdnsbl::ini $bl reply:$lastOctet]
            return $reason
        }
        return "Unknown"
    }

    # Getter to retrieve a ban reason
    proc getBanReason { bl } {
        if {[::ini::exists $::zapdnsbl::ini $bl ban_message]} {
            return [::ini::value $::zapdnsbl::ini $bl ban_message]
        } elseif {[::ini::exists $::zapdnsbl::ini $bl default_ban_message]} {
            return [::ini::value $::zapdnsbl::ini $bl default_ban_message]
        }
        return ""
    }

    # Getter to retrieve ban_unknown from a blacklist, returns true or false
    proc isBanUnknownEnabled { bl } {
        if {[::ini::exists $::zapdnsbl::ini $bl ban_unknown] && [string tolower [::ini::value $::zapdnsbl::ini $bl ban_unknown]] == "true"} {
            return 1
        }
        return 0
    }
}

namespace eval ::stderreu {
    variable helpfuncs

    if {![info exists ::stderreu::helpfuncs] || ![dict exists $::stderreu::helpfuncs zapdnsbl]} {
        dict set ::stderreu::helpfuncs zapdnsbl [list zapdnsbl zapblcheck]
    }

    proc zapdnsbl { idx } {
        putidx $idx "\n\n\002$::zapdnsbl::longName v$::zapdnsbl::version\002 by Ratler"
        ::stderreu::zapblcheck $idx
    }

    proc zapblcheck { idx } {
        putidx $idx "### \002zapblcheck <host>"
    }

    proc zapdnsbldefault { idx } {
        putidx $idx "\n\n\002$::zapdnsbl::longName v$::zapdnsbl::version\002 commands:"
        putidx $idx "   \002zapblcheck\002"
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


putlog "\002$::zapdnsbl::longName v$::zapdnsbl::version\002 by Ratler loaded"
