#
# zapdnsbl.tcl  Version: 0.7-kiril-dev  Author: Stefan Wold <ratler@stderr.eu>
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
# Copyright (C) 2010 - 2016  Stefan Wold <ratler@stderr.eu>
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
setudef flag zapdnsbl.hexlookup
setudef int zapdnsbl.bantime

# Packages
package require Tcl 8.5
package require inifile
package require ip

# Bindings
bind evnt - prerehash ::zapdnsbl::onEvent
bind evnt - save ::zapdnsbl::onEvent
bind evnt - sigquit ::zapdnsbl::onEvent
bind evnt - sigterm ::zapdnsbl::onEvent
bind join - * ::zapdnsbl::onJoin
bind raw - NOTICE ::zapdnsbl::onServerNotice
bind dcc m|o zapblconfig ::zapdnsbl::dccConfig
bind dcc - help ::stderreu::help
bind pub - !zapblcheck ::zapdnsbl::pubCheckDnsbl

# Print debug
proc ::zapdnsbl::debug { text } {
    putloglev $::zapdnsbl::conflag * "$::zapdnsbl::name - DEBUG: $text"
}

namespace eval ::zapdnsbl {
    # Global variables
    variable version "0.8-kiril-dev"
    variable name "zapdnsbl"
    variable longName "ZAP DNS Blacklist"
    variable ini
    variable exemptCidrList

    # Parse INI file
    if {[file exists $::zapdnsbl::inifile]} {
        # Open ini file in read-write mode for easy updating
        set ::zapdnsbl::ini [::ini::open $::zapdnsbl::inifile r+]
        foreach section [::ini::sections $::zapdnsbl::ini] {
            if {[regexp {^bl\:} $section]} {
                ::zapdnsbl::debug "Loading blacklist '$section'"
            } else {
                ::zapdnsbl::debug "Loading $::zapdnsbl::name '$section'"
            }
        }

        # Parse CIDR file
        if {[::ini::exists $::zapdnsbl::ini "config"] && [::ini::exists $::zapdnsbl::ini "config" "exempt_cidr_file"]} {
            set cidr [::ini::value $::zapdnsbl::ini "config" "exempt_cidr_file"]
            if {[file exists $cidr]} {
                ::zapdnsbl::debug "Loading CIDR list from $cidr"
                set fcidr [open $cidr]
                while {![eof $fcidr]} {
                    gets $fcidr line
                    if {[regexp {^[0-9]} $line]} {
                        regexp -nocase {^([0-9\.\/]+)} $line -> mask
                        lappend ::zapdnsbl::exemptCidrList $mask
                    }
                }
                close $fcidr
                ::zapdnsbl::debug "CIDR file loaded with [llength $::zapdnsbl::exemptCidrList] netmask(s)"
            }
        } else {
            ::zapdnsbl::debug "Missing 'config' section and/or key 'exempt_cidr_list=/path/to/cidr.txt'"
        }
    }
}
###
# Functions
###
proc ::zapdnsbl::saveAndCloseIniFile { } {
    putlog "$::zapdnsbl::name - Saving ini file"
    ::ini::commit $::zapdnsbl::ini
    ::ini::close $::zapdnsbl::ini
}

# onEvent: Used to watch certain events to act upon
proc ::zapdnsbl::onEvent { type } {
    ::zapdnsbl::debug "EVENT $type"
    switch -- $type {
        prerehash {
            ::ini::close $::zapdnsbl::ini
        }
        sigquit {
            ::zapdnsbl::saveAndCloseIniFile
        }
        sigterm {
            ::zapdnsbl::saveAndCloseIniFile
        }
    }
}

proc ::zapdnsbl::onJoin { nick host handle channel } {
    # Ignore myself
    if {[isbotnick $nick]} {
        ::zapdnsbl::debug "Found myself ($nick) - Ignoring"
        return 1
    }

    # Lower case channel
    set channel [string tolower $channel]

    # Only run if channel is defined
    if {![channel get $channel zapdnsbl]} { return 1 }

    # Exclude ops, voice, friends
    if {[matchattr $handle o|o $channel]} {
        putlog  "$::zapdnsbl::name - $nick is on exempt list"
        return 1
    }

    # Special stuff for kiril
    if {[regexp {(?i)^[A-F0-9]{8}@.*(\.html\.chat|\.kiwiirc\.com)$} $host]} {
        if {![channel get $channel zapdnsbl.hexlookup]} { return 1 }
    }
    set data [::zapdnsbl::getIpHost $host]
    if {[dict get $data iphost] == 0} { return 1 }
    dict set data host $host
    dict set data iphost $iphost
    dict set data channel $channel
    dict set data nick $nick
    dict set data pub 0

    dnslookup $iphost ::zapdnsbl::resolveCallback $data
}

proc ::zapdnsbl::onServerNotice { from keyword text } {
    if {[string match "*Client connecting:*" $text]} {
        regexp {.*\((.+@[^\)]+)} $text matched host
        set data [::zapdnsbl::getIpHost $host]
        if {[dict get $data iphost] == 0} { return 1 }
        ::zapdnsbl::debug "Host: $host = [dict get $data iphost]"
        dict set data host $host
        dict set data channel 0
        dict set data nick 0
        dict set data pub 0

        dnslookup [dict get $data iphost] ::zapdnsbl::resolveCallback $data
    }
}

proc ::zapdnsbl::getIpHost { host } {
    if {[regexp {(?i)^[A-F0-9]{8}@.*(\.html\.chat|\.kiwiirc\.com)$} $host]} {
        regexp "(.+)@.+" $host -> hex
        dict set data webchat 1
        set iphost [::zapdnsbl::getIPFromHex $hex]
    } else {
        regexp ".+@(.+)" $host -> iphost
        set iphost [string tolower $iphost]
    }
    dict set data iphost $iphost
    return $data
}

proc ::zapdnsbl::resolveCallback { ip hostname status data } {
    # DNS lookup successfull?
    if {$status == 0 && ![regexp {[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $hostname]} {
        ::zapdnsbl::debug "Couldn't resolve '$hostname'. No further action taken."
        return 0
    }

    # Reverse the IP
    regexp {([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3}).([0-9]{1,3})} $ip -> oct1 oct2 oct3 oct4
    set reverseIp "$oct4.$oct3.$oct2.$oct1"

    ::zapdnsbl::debug "Checking host '[dict get $data nick]![dict get $data host]' - ip $ip - channel [dict get $data channel]"
    foreach bl [::ini::sections $::zapdnsbl::ini] {
        ::zapdnsbl::debug "Trying blacklist $bl ($ip)"
        if {[regexp {^bl\:} $bl]} {
            set dnsbl [lindex [split $bl ":"] end]
            dict set data blacklist $bl
            dict set data ip $ip
            dict set data hostname $hostname
            if {[dict get $data pub] == 0} {
                dnslookup $reverseIp.$dnsbl ::zapdnsbl::dnsblCallback $data
            } else {
                dnslookup $reverseIp.$dnsbl ::zapdnsbl::dnsblPubCallback $data
            }
        }
    }
}

proc ::zapdnsbl::dnsblCallback { ip hostname status data } {
    set host [dict get $data host]
    set nick [dict get $data nick]
    set blacklist [dict get $data blacklist]
    set channel [dict get $data channel]
    set dnsblData [::zapdnsbl::getDnsblData $ip $hostname $status $data]
    regexp ".+@(.+)" $host -> iphost

    if {[dict get $dnsblData status] == "FOUND" } {
        # Check if unknown is enabled or abort
        if {![::zapdnsbl::isBanUnknownEnabled "[dict get $dnsblData blacklist]"] && [dict get $dnsblData reason] == "Unknown"} {
            ::zapdnsbl::debug "Host '[dict get $dnsblData hostname] ([dict get $data ip])' found in [dict get $dnsblData blacklist] reason '[dict get $dnsblData reason]', will not ban because ban_unknown is set to false"
            return 1
        }

        if {$channel != 0} {
            set bantime [channel get $channel zapdnsbl.bantime]
            if {$bantime == 0} {
                putlog "$::zapdnsbl::name - Bantime not set, defaulting to 120 minutes, set with .chanset $channel zapdnsbl.bantime <integer>."
                set bantime 120
            }
        } else {
            # Check exempt here since this is the place where we have the actual IP resolved
            if {[::ip::longestPrefixMatch [dict get $data ip] $::zapdnsbl::exemptCidrList] != ""} {
                ::zapdnsbl::debug "$host ([dict get $data ip]) is on the exempt list"
                return 1
            }
        }

        if {[dict exists $data webchat]} {
            regexp {(.+)@[^\.]+\.(.+)} $host -> hex webHost

            if {$channel == 0} {
                ::zapdnsbl::debug "Adding webchat KLINE for *$hex@*.$webHost"
                putquick "KLINE 1440 *$hex@*.$webHost :[dict get $dnsblData banreason]"
                ::zapdnsbl::notifyBackChannel "KLINE 1440 *$hex@*.$webHost :[dict get $dnsblData banreason]"
            } else {
                ::zapdnsbl::debug "Ban webchat before newchanban: $hex"
                if {[matchban "*!$hex@*.html.chat" $channel]} {
                    ::zapdnsbl::debug "Ban webchat matchban: $hex"
                    return 1
                }
                putquick "KICK $channel $nick :[dict get $dnsblData banreason]"
                putquick "MODE $channel +b *!*$hex@*.html.chat"
                ::zapdnsbl::debug "Ban webchat after newchanban: $hex"
            }
        } else {
            if {$channel == 0} {
                ::zapdnsbl::debug "Adding KLINE for *@$iphost"
                putquick "KLINE 1440 *@$iphost :[dict get $dnsblData banreason]"
                ::zapdnsbl::notifyBackChannel "KLINE 1440 *@$iphost :[dict get $dnsblData banreason]"
            } else {
                if {[matchban "*!*@$iphost" $channel]} { return 1 }
                newchanban $channel "*!*@$iphost" $::zapdnsbl::name [dict get $dnsblData banreason] $bantime
            }
        }
        putlog "$::zapdnsbl::name - Host '[dict get $data host] ([dict get $data ip])' found in [dict get $dnsblData blacklist] reason '[dict get $dnsblData reason]' on channel '$channel', banning with reason '[dict get $dnsblData banreason]'!"
    }
}

proc ::zapdnsbl::notifyBackChannel { msg } {
    if {[::ini::exists $::zapdnsbl::ini config backchan] && [botonchan [::ini::value $::zapdnsbl::ini config backchan]]} {
        set backchan [::ini::value $::zapdnsbl::ini options backchan]
        puthelp "PRIVMSG $backchan :$msg"
    }
}

# Public channel command to check if host appear in a DNS blacklist
proc ::zapdnsbl::pubCheckDnsbl { nick host handle channel arg } {
    if {![channel get $channel zapdnsbl.pubcmd]} { return 0 }

    dict set data nick $nick
    dict set data channel $channel
    dict set data pub 1

    dnslookup $arg ::zapdnsbl::resolveCallback $data
}

proc ::zapdnsbl::dnsblPubCallback { ip hostname status data } {
    set channel [dict get $data channel]
    set nick [dict get $data nick]
    set bl [lindex [split [dict get $data blacklist] :] 1]
    set dnsblData [::zapdnsbl::getDnsblData $ip $hostname $status $data]

    if {[dict get $dnsblData status] == "FOUND"} {
        puthelp "PRIVMSG $channel :$nick: $::zapdnsbl::name - Host [dict get $data ip] ([dict get $data hostname]) found in $bl reason '[dict get $dnsblData reason]'"
    }
}

proc ::zapdnsbl::dccConfig { nick idx arg } {
    if {!([llength [split $arg]] > 0)} {
        ::stderreu::zapblconfig $idx; return 0
    }

    set key [string tolower [lindex [split $arg] 0]]
    set value [join [lrange [split $arg] 1 end]]


    # Allowed string options
    set allowed_str_opts [list bl]

    # Allowed boolean options
    #set allowed_bool_opts [list ]
    if {[lsearch -exact $allowed_str_opts $key] != -1} {
        if {$key == "bl"} {
            if {[llength [split $value]] > 0} {
                set action [lindex [split $value] 0]

                switch -- $action {
                    list {
                        putidx $idx "### $::zapdnsbl::name - Loaded blacklists"
                        foreach section [::ini::sections $::zapdnsbl::ini] {
                            if {[regexp {^bl\:} $section]} {
                                putidx $idx "   [lindex [split $section ":"] 1]"
                                foreach {k v} [::ini::get $::zapdnsbl::ini $section] {
                                    putidx $idx "      $k = $v"
                                }
                                putidx $idx ""
                            }
                        }
                    }
                    default {
                        putidx $idx "$::zapdnsbl::name - Unknown action '$action'."
                        ::stderreu::zapblconfig $idx
                    }
                }
            } else {
                putidx $idx "$::zapdnsbl::name - Missing arguments."
                ::stderreu::zapblconfig $idx
            }
        } elseif {$value != ""} {
            ::zapdnsbl::setConfigValuePair options $key $value
            putdcc $idx "$::zapdnsbl::name: Option '$key' set with the value '$value'"
        } else {
            ::zapdnsbl::setConfigValuePair options $key ""
            putdcc $idx "$::zapdnsbl::name: Option '$key' unset"
        }
    }
}

proc ::zapdnsbl::getDnsblData { ip hostname status data } {
    set blacklist [dict get $data blacklist]

    # Default dnsbl stuff
    dict set dnsblData status "OK"
    dict set dnsblData hostname $hostname

    if {$status == 1 && [regexp {^[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}$} $ip]} {
        dict set dnsblData status "FOUND"

        set reason [::zapdnsbl::getDnsblReason $blacklist $ip]
        set template [list %reason% $reason \
                          %ip% [dict get $data ip]]
        dict set dnsblData reason $reason
        dict set dnsblData banreason [::zapdnsbl::template [::zapdnsbl::getBanReason $blacklist] $template]
        dict set dnsblData blacklist $blacklist
    }
    return $dnsblData
}

# This function will replace %keywords% with supplied substitutes
proc ::zapdnsbl::template { text subs } {
    foreach {arg1 arg2} $subs {
        regsub -all -- $arg1 $text $arg2 text
    }
    return $text
}

###
# Getters
###

# Getter to retrieve a reason from the ini file
proc ::zapdnsbl::getDnsblReason { bl address } {
    # Last octet in $address is the reason matched against reply:X
    set lastOctet [lindex [split $address "."] end]
    if {[::ini::exists $::zapdnsbl::ini $bl reply:$lastOctet]} {
        set reason [::ini::value $::zapdnsbl::ini $bl reply:$lastOctet]
        return $reason
    }
    return "Unknown"
}

# Getter to retrieve a ban reason
proc ::zapdnsbl::getBanReason { bl } {
    if {[::ini::exists $::zapdnsbl::ini $bl ban_message]} {
        return [::ini::value $::zapdnsbl::ini $bl ban_message]
    } elseif {[::ini::exists $::zapdnsbl::ini $bl default_ban_message]} {
        return [::ini::value $::zapdnsbl::ini $bl default_ban_message]
    }
    return ""
}

# Getter to retrieve ban_unknown from a blacklist, returns true or false
proc ::zapdnsbl::isBanUnknownEnabled { bl } {
    if {[::ini::exists $::zapdnsbl::ini $bl ban_unknown] && [string tolower [::ini::value $::zapdnsbl::ini $bl ban_unknown]] == "true"} {
        return 1
    }
    return 0
}

# Translate hex string to ip
proc ::zapdnsbl::getIPFromHex { hex } {
    # Simple check to validate proper hex string
    if {[regexp {^[a-fA-F0-9]{8}$} $hex]} {
        set dec [expr 0x$hex]
        set o1 [expr {($dec >> 24) & 0xff}]
        set o2 [expr {($dec >> 16) & 0xff}]
        set o3 [expr {($dec >> 8) & 0xff}]
        set o4 [expr {$dec & 0xff}]

        return "$o1.$o2.$o3.$o4"
    }
    return 0
}

###
# Setters
###
proc ::zapdnsbl::setConfigValuePair { section key value } {
    # If value is empty remove the key
    if {$value == ""} {
        ::ini::delete $::zapdnsbl::ini $section $key
    } else {
        ::ini::set $::zapdnsbl::ini $section $key $value
    }
    # Check if section have keys if not delete the section
    if {[llength [::ini::keys $::zapdnsbl::ini $section]] == 0} {
        ::ini::delete $::zapdnsbl::ini $section
        ::zapdnsbl::debug "Section '$section' empty - deleted"
    }
}

namespace eval ::stderreu {
    variable helpfuncs

    dict set ::stderreu::helpfuncs zapdnsbl [list zapdnsbl zapblcheck zapblconfig]
}

proc ::stderreu::zapdnsbl { idx } {
    putidx $idx "\n\n\002$::zapdnsbl::longName v$::zapdnsbl::version\002 by Ratler"
    ::stderreu::zapblcheck $idx
}

proc ::stderreu::zapblcheck { idx } {
    putidx $idx "### \002zapblcheck <host>"
}

proc ::stderreu::zapblconfig { idx } {
    putidx $idx "### \002zablconfig <option> \[value\]\002"
    putidx $idx "    \002Options\002:"
    putidx $idx "      bl <action>           : Manage blacklists"
    putidx $idx "                              Valid actions: list"
    putidx $idx "    \002*NOTE*\002:"
    putidx $idx "      To completely remove an option from the configuration leave \[value\] blank, ie .zapblconfig nameserver"
}
proc ::stderreu::zapdnsbldefault { idx } {
    putidx $idx "\n\n\002$::zapdnsbl::longName v$::zapdnsbl::version\002 commands:"
    putidx $idx "   \002zapblcheck    zapblconfig\002"
}

proc ::stderreu::help { hand idx arg } {
    set myarg [join $arg]
    set found 0
    # First we test if arg is all to print eggdrop builtin commands,
    # then we call the help proc ::stderreu::for each script loaded
    if {$myarg == "all"} {
        *dcc:help $hand $idx [join $arg]
        foreach key [dict keys $::stderreu::helpfuncs] {
            ::stderreu::$key $idx
        }
        return 1
    } else {
        foreach key [dict keys $::stderreu::helpfuncs] {
            foreach helpf [dict get $::stderreu::helpfuncs $key] {
                if {[string match -nocase $myarg $helpf]} {
                    ::stderreu::$helpf $idx
                    set found 1
                }
            }
        }
    }

    if {$found == 0 || [regexp {\*} $myarg]} {
        *dcc:help $hand $idx $myarg
    }

    if {[llength [split $arg]] == 0} {
        foreach key [dict keys $::stderreu::helpfuncs] {
            ::stderreu::${key}default $idx
        }
    }
    return 1
}

putlog "\002$::zapdnsbl::longName v$::zapdnsbl::version\002 by Ratler loaded"
