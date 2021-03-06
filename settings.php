<?php
// This file is part of Moodle - http://moodle.org/.
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle. If not, see <http://www.gnu.org/licenses/>.
 
/**
 * @package local
 * @subpackage userinfosync
 * @copyright 2013 Ivan Šakić
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
defined('MOODLE_INTERNAL') or die;

if ($hassiteconfig) {
    $userinfosyncsettings = new admin_settingpage('local_userinfosync', get_string('pluginname', 'local_userinfosync'));
    $userinfosyncsettings->add(new admin_setting_configcheckbox('userinfosync_hosttype', get_string('hosttype', 'local_userinfosync'), get_string('confighosttype','local_userinfosync'), 'idp', 'idp','subscriber'));
    // trusted peers
    $userinfosyncsettings->add(new admin_setting_configtextarea('userinfosync_trustedpeers', get_string('trustedpeers', 'local_userinfosync'), get_string('configtrustedpeers', 'local_userinfosync'), '')); 
    
    $ADMIN->add('localplugins', $userinfosyncsettings);
}
