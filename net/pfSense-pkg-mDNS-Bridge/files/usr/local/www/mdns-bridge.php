<?php
/*
 * mdns-bridge.php
 *
 * part of pfSense (https://www.pfsense.org)
 * Copyright (c) 2024-2026 Denny Page
 * All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


require_once("guiconfig.inc");
require_once("mdns-bridge.inc");

$shortcut_section = 'mdns-bridge';

// Configuration paths
$package_path = 'installedpackages/mdns-bridge';
$path_enable = 'enable';
$path_carp_vhid = 'carp_vhid';
$path_active_interfaces = 'active_interfaces';
$path_decode_warnings = 'decode_warnings';
$path_global_ip_protocols = 'global_ip_protocols';
$path_global_filter_type = 'global_filter_type';
$path_global_filter_list = 'global_filter_list';
$path_interfaces = 'interfaces';

// Get the current configuration
$current_config = config_get_path($package_path, []);
$pconfig['enable'] = array_get_path($current_config, $path_enable);
$pconfig['carp_vhid'] = array_get_path($current_config, $path_carp_vhid);
$pconfig['active_interfaces'] = array_filter(explode(',', array_get_path($current_config, $path_active_interfaces, '')));
$pconfig['decode_warnings'] = array_get_path($current_config, $path_decode_warnings);
$pconfig['global_ip_protocols'] = array_get_path($current_config, $path_global_ip_protocols, 'both');
$pconfig['global_filter_type'] = array_get_path($current_config, $path_global_filter_type, 'none');
$pconfig['global_filter_list'] = array_get_path($current_config, $path_global_filter_list, '');
$pconfig['interfaces'] = array_get_path($current_config, $path_interfaces, []);

// Avahi conflict
$avahi_enabled = config_get_path('installedpackages/avahi/config/0/enable', false) &&
		 config_get_path('installedpackages/avahi/config/0/reflection', false);

// Get the list of available interfaces
$available_interfaces = get_configured_interface_with_descr();
foreach ($available_interfaces as $interface => $name) {
	if (interface_has_gateway($interface) || interface_has_gatewayv6($interface)) {
		unset($available_interfaces[$interface]);
	}
}

if ($_POST) {
	unset($input_errors);
	$pconfig = $_POST;

	// Check for Avahi conflict
	if ($pconfig['enable'] && $avahi_enabled) {
		$input_errors[] = gettext('Avahi reflection must be disabled before enabling mDNS Bridge');
	}

	// Validate interfaces
	$pconfig['active_interfaces'] = array_get_path($pconfig, 'active_interfaces', []);
	if (count($pconfig['active_interfaces']) < 2) {
		$input_errors[] = gettext('A minimum of two interfaces are required');
	}

	// Validate and normalize the global filter
	$type = $pconfig['global_filter_type'];
	if ($type == 'allow' || $type == 'deny') {
		$list = trim($pconfig['global_filter_list']);
		if ($list == '') {
			$pconfig['global_filter_type'] = 'none';
			$pconfig['global_filter_list'] = '';
		}
		else if ($list == '<all>') {
			if ($type == 'allow') {
				$pconfig['global_filter_type'] = 'none';
			}
			else {
				$input_errors[] = sprintf(gettext('"%1$s" is an invalid Global Filter'), $list);
			}
		}
		else {
			$filter_list = array();
			foreach (array_filter(explode(',', $list)) as $filter) {
				$filter = trim($filter);
				if (str_contains($filter, '..')) {
					$input_errors[] = sprintf(gettext('Invalid name in Global Filter List: "%1$s"'), $filter);
				}
				$filter_list[] = $filter;
			}
			$pconfig['global_filter_list'] = implode(', ', $filter_list);
		}
	}

	// Validate and normalize the interface filters
	foreach ($pconfig['active_interfaces'] as $interface) {
		// Inbound filter
		$type = $pconfig['inbound_filter_type_' . $interface];
		if ($type == 'allow' || $type == 'deny') {
			$list = trim($pconfig['inbound_filter_list_' . $interface]);
			if ($list == '') {
				$pconfig['inbound_filter_type_' . $interface] = 'none';
				$pconfig['inbound_filter_list_' . $interface] = '';
			}
			else if ($list == '<all>') {
				if ($type == 'allow') {
					$pconfig['inbound_filter_type_' . $interface] = 'none';
				}
				else {
					$pconfig['inbound_filter_type_' . $interface] = 'deny_all';
				}
				$pconfig['inbound_filter_list_' . $interface] = '';
			}
			else {
				$filter_list = array();
				foreach (array_filter(explode(',', $list)) as $filter) {
					$filter = trim($filter);
					if (str_contains($filter, '..')) {
						$input_errors[] = sprintf(gettext('Invalid name in %1$s -> Inbound Filter List: "%2$s"'),
							convert_friendly_interface_to_friendly_descr($interface), $filter);
					}
					$filter_list[] = $filter;
				}
				$pconfig['inbound_filter_list_' . $interface] = implode(', ', $filter_list);
			}
		}

		// Outbound filter
		$type = $pconfig['outbound_filter_type_' . $interface];
		if ($type == 'allow' || $type == 'deny') {
			$list = trim($pconfig['outbound_filter_list_' . $interface]);
			if ($list == '') {
				$pconfig['outbound_filter_type_' . $interface] = 'none';
				$pconfig['outbound_filter_list_' . $interface] = '';
			}
			else if ($list == '<all>') {
				if ($type == 'allow') {
					$pconfig['outbound_filter_type_' . $interface] = 'none';
				}
				else {
					$pconfig['outbound_filter_type_' . $interface] = 'deny_all';
				}
				$pconfig['outbound_filter_list_' . $interface] = '';
			}
			else {
				$filter_list = array();
				foreach (array_filter(explode(',', $list)) as $filter) {
					$filter = trim($filter);
					if (str_contains($filter, '..')) {
						$input_errors[] = sprintf(gettext('Invalid name in %1$s -> Outbound Filter List: "%2$s"'),
							convert_friendly_interface_to_friendly_descr($interface), $filter);
					}
					$filter_list[] = $filter;
				}
				$pconfig['outbound_filter_list_' . $interface] = implode(', ', $filter_list);
			}
		}

		// Peer filters
		$found_peers = 0;
		foreach ($pconfig['active_interfaces'] as $peer) {
			if ($peer == $interface) {
				continue;
			}
			$type = $pconfig['peer_filter_type_' . $interface . '_' . $peer];
			if ($type == 'allow' || $type == 'deny') {
				$list = trim($pconfig['peer_filter_list_' . $interface . '_' . $peer]);
				if ($list == '') {
					$pconfig['peer_filter_type_' . $interface . '_' . $peer] = 'none';
					$pconfig['peer_filter_list_' . $interface . '_' . $peer] = '';
				}
				else if ($list == '<all>') {
					if ($type == 'allow') {
						$pconfig['peer_filter_type_' . $interface . '_' . $peer] = 'none';
					}
					else {
						$pconfig['peer_filter_type_' . $interface . '_' . $peer] = 'deny_all';
					}
					$pconfig['peer_filter_list_' . $interface . '_' . $peer] = '';
				}
				else {
					$filter_list = array();
					foreach (array_filter(explode(',', $list)) as $filter) {
						$filter = trim($filter);
						if (str_contains($filter, '..')) {
							$input_errors[] = sprintf(gettext('Invalid name in %1$s -> Peer Filter List %2$s: "%3$s"'),
								convert_friendly_interface_to_friendly_descr($interface),
								convert_friendly_interface_to_friendly_descr($peer),
								$filter);
						}
						$filter_list[] = $filter;
					}
					$pconfig['peer_filter_list_' . $interface . '_' . $peer] = implode(', ', $filter_list);
				}
			}

			if ($pconfig['peer_filter_type_' . $interface . '_' . $peer] != 'none') {
				$found_peers = 1;
			}
		}
		if (!$found_peers) {
			// If no peer filters are actually defined, unset the enable flag
			unset($pconfig['enable_peer_filters_' . $interface]);
		}
	}

	// Rebuild the interfaces array
	foreach ($available_interfaces as $interface => $name) {
		array_set_path($pconfig, "interfaces/{$interface}/ip_protocols", $pconfig['ip_protocols_' . $interface]);
		array_set_path($pconfig, "interfaces/{$interface}/inbound_filter_type", $pconfig['inbound_filter_type_' . $interface]);
		array_set_path($pconfig, "interfaces/{$interface}/inbound_filter_list", $pconfig['inbound_filter_list_' . $interface]);
		array_set_path($pconfig, "interfaces/{$interface}/outbound_filter_type", $pconfig['outbound_filter_type_' . $interface]);
		array_set_path($pconfig, "interfaces/{$interface}/outbound_filter_list", $pconfig['outbound_filter_list_' . $interface]);
		array_set_path($pconfig, "interfaces/{$interface}/enable_peer_filters", $pconfig['enable_peer_filters_' . $interface]);
		$peer_array = array();
		foreach ($available_interfaces as $peer => $peer_name) {
			if ($peer == $interface) {
				continue;
			}
			array_set_path($peer_array, "{$peer}/filter_type", $pconfig['peer_filter_type_' . $interface . '_' . $peer]);
			array_set_path($peer_array, "{$peer}/filter_list", $pconfig['peer_filter_list_' . $interface . '_' . $peer]);
		}
		array_set_path($pconfig, "interfaces/{$interface}/peers", $peer_array);
	}

	// Update the config
	if (!$input_errors) {
		// Global settings
		array_set_path($current_config, $path_enable, $pconfig['enable']);
		array_set_path($current_config, $path_carp_vhid, $pconfig['carp_vhid']);
		array_set_path($current_config, $path_active_interfaces, implode(',', $pconfig['active_interfaces']));
		array_set_path($current_config, $path_decode_warnings, $pconfig['decode_warnings']);
		array_set_path($current_config, $path_global_ip_protocols, $pconfig['global_ip_protocols']);
		array_set_path($current_config, $path_global_filter_type, $pconfig['global_filter_type']);
		array_set_path($current_config, $path_global_filter_list, $pconfig['global_filter_list']);

		// Interface settings
		foreach ($pconfig['active_interfaces'] as $interface) {
			array_set_path($current_config, "{$path_interfaces}/{$interface}/ip_protocols", $pconfig['ip_protocols_' . $interface]);
			array_set_path($current_config, "{$path_interfaces}/{$interface}/inbound_filter_type", $pconfig['inbound_filter_type_' . $interface]);
			array_set_path($current_config, "{$path_interfaces}/{$interface}/inbound_filter_list", $pconfig['inbound_filter_list_' . $interface]);
			array_set_path($current_config, "{$path_interfaces}/{$interface}/outbound_filter_type", $pconfig['outbound_filter_type_' . $interface]);
			array_set_path($current_config, "{$path_interfaces}/{$interface}/outbound_filter_list", $pconfig['outbound_filter_list_' . $interface]);
			array_set_path($current_config, "{$path_interfaces}/{$interface}/enable_peer_filters", $pconfig['enable_peer_filters_' . $interface]);
			$peer_array = array();
			foreach ($available_interfaces as $peer => $peer_name) {
				if ($peer == $interface) {
					continue;
				}

				array_set_path($peer_array, "{$peer}/filter_type", $pconfig['peer_filter_type_' . $interface . '_' . $peer]);
				array_set_path($peer_array, "{$peer}/filter_list", $pconfig['peer_filter_list_' . $interface . '_' . $peer]);
			}
			array_set_path($current_config, "{$path_interfaces}/{$interface}/peers", $peer_array);
		}

		// Write the config
		config_set_path($package_path, $current_config);
		write_config(gettext("mDNS Bridge settings changed"));

		// Sync the running configuration
		mdns_bridge_sync_config();
	}
}


$ip_protocol_types = array(
	'both' => gettext('IPv4 and IPv6'),
	'ipv4' => gettext('IPv4 only'),
	'ipv6' => gettext('IPv6 only') );

$global_filter_types = array(
	'none' => gettext('All mDNS names are allowed'),
	'allow' => gettext('mDNS names that match the filter list are allowed'),
	'deny' => gettext('mDNS names that match the filter list are denied') );

$interface_filter_types = array(
	'none' => gettext('All mDNS names are allowed'),
	'allow' => gettext('mDNS names that match the filter list are allowed'),
	'deny' => gettext('mDNS names that match the filter list are denied'),
	'deny_all' => gettext('All mDNS names are denied') );

$peer_filter_types = array(
	'none' => gettext('Disabled'),
	'allow' => gettext('mDNS names that match the filter list are allowed'),
	'deny' => gettext('mDNS names that match the filter list are denied'),
	'deny_all' => gettext('All mDNS names are denied') );

$filter_help_text = gettext(
	'Comma separated list of mDNS names. Most often, a name should ' .
	'be a single label representing a service name such as ' .
	'_printer, _ipp, _ipps, _airplay, _hap, _http or _ssh.');

$filter_placeholder_text = gettext('name1, name2, name3');


$pgtitle = array(gettext("Services"), gettext("mDNS Bridge"));
include("head.inc");

if ($input_errors) {
	print_input_errors($input_errors);
}

$form = new Form;
$section = new Form_Section('General Settings');

// Enable
$section->addInput(new Form_Checkbox(
	'enable',
	'Enable',
	'Enable the mDNS Bridge daemon',
	$pconfig['enable']
));

// CARP
$section->addInput(new Form_Select(
	'carp_vhid',
	'CARP Status VHID',
	$pconfig['carp_vhid'],
	mdns_bridge_get_carp_list()
))->setHelp(gettext('Used for HA MASTER/BACKUP status. mDNS Bridge will be started when the chosen VHID is in MASTER status, and stopped when in BACKUP status.'));

// List of interfaces
$section->addInput(new Form_Select(
	'active_interfaces',
	'*Interfaces',
	$pconfig['active_interfaces'],
	$available_interfaces,
	true
))->addClass('active_interfaces')->setHelp(gettext('Interfaces that the mDNS Bridge daemon will operate on. Two or more interfaces are required.'));
$form->add($section);

// Decode warnings
$section->addInput(new Form_Checkbox(
	'decode_warnings',
	'Decode Warnings',
	'Enable warnings for mDNS decoding errors that are silent by default',
	$pconfig['decode_warnings']
));

$section = new Form_Section('Global Settings');
// Global IP protocol list
$section->addInput(new Form_Select(
	'global_ip_protocols',
	'IP Protocols',
	$pconfig['global_ip_protocols'],
	$ip_protocol_types
))->setHelp(gettext('Select which IP protocols mDNS Bridge will operate on.'));

// Global filter type
$group = new Form_Group('Global Filter Type');
$group->add(new Form_Select(
	'global_filter_type',
	null,
	$pconfig['global_filter_type'],
	$global_filter_types
))->setHelp(gettext('The global filter is applied to incoming packets on all interfaces prior to any interface specific filters.'));
$section->add($group);

$group = new Form_Group('Global Filter List');
$group->addClass('sh_global_filter_list');
$group->add(new Form_Input(
	'global_filter_list',
	null,
	'text',
	$pconfig['global_filter_list']
))->setHelp($filter_help_text)->setWidth(7)->setAttribute('placeholder', $filter_placeholder_text);
$section->add($group);
$form->add($section);

// Interface sections
foreach ($available_interfaces as $interface => $name) {
	$interface_config = array_get_path($pconfig, "interfaces/{$interface}", []);

	$section = new Form_Section($name . ' Settings');
	$section->addClass('sh_interface');
	$section->addClass('sh_interface_' . $interface);

	// IP protocols
	$group = new Form_Group('IP Protocols');
	$group->addClass('sh_interface_protocols');
	$group->add(new Form_Select(
		'ip_protocols_' . $interface,
		null,
		$interface_config['ip_protocols'],
		$ip_protocol_types
	))->setHelp(gettext('Select which IP protocols mDNS Bridge will operate on.'));
	$section->add($group);

	// Inbound filter type
	$group = new Form_Group('Inbound Filter Type');
	$group->add(new Form_Select(
		'inbound_filter_type_' . $interface,
		null,
		$interface_config['inbound_filter_type'],
		$interface_filter_types
	))->setHelp(gettext('The inbound filter is applied to packets received on the interface following the global filter.'));
	$section->add($group);

	$group = new Form_Group('Inbound Filter List');
	$group->addClass('sh_interface_inbound_filter_list_' . $interface);
	$group->add(new Form_Input(
		'inbound_filter_list_' . $interface,
		null,
		'text',
		array_get_path($interface_config, 'inbound_filter_list', ''))
	)->setHelp($filter_help_text)->setWidth(7)->setAttribute('placeholder', $filter_placeholder_text);
	$section->add($group);

	// Outbound filter type
	$group = new Form_Group('Outbound Filter Type');
	$group->add(new Form_Select(
		'outbound_filter_type_' . $interface,
		null,
		$interface_config['outbound_filter_type'],
		$interface_filter_types
	))->setHelp(gettext('The outbound filter is applied to packets prior to sending packets on the interface.'));
	$section->add($group);

	// Outbound filter list
	$group = new Form_Group('Outbound Filter List');
	$group->addClass('sh_interface_outbound_filter_list_' . $interface);
	$group->add(new Form_Input(
		'outbound_filter_list_' . $interface,
		null,
		'text',
		array_get_path($interface_config, 'outbound_filter_list', ''))
	)->setHelp($filter_help_text)->setWidth(7)->setAttribute('placeholder', $filter_placeholder_text);
	$section->add($group);

	// Peer specific outbound filters
	$group = new Form_Group('Peer Filters');
	$group->add(new Form_Checkbox(
		'enable_peer_filters_' . $interface,
		null,
		'Enable peer specific outbound filters',
		$interface_config['enable_peer_filters'],
	))->setHelp(gettext('Enable the use of individual outbound filters based on the source interface of the mDNS packet. When enabled, a peer specific filter overrides (replaces) the interface outbound filter for packets that originate from the specified peer interface.'))->setWidth(7);
	$section->add($group);

	foreach ($available_interfaces as $peer => $peer_name) {
		if ($peer == $interface) {
			continue;
		}
		$peer_config = array_get_path($interface_config, "peers/{$peer}", []);

		// Peer filter type
		$group = new Form_Group('Peer Filter Type ' . $peer_name);
		$group->addClass('sh_peer_' . $interface);
		$group->addClass('sh_peer_filter_type_' . $interface . '_' . $peer);
		$group->add(new Form_Select(
			'peer_filter_type_' . $interface . '_' . $peer,
			null,
			$peer_config['filter_type'],
			$peer_filter_types
		))->setHelp(gettext('If enabled, this filter is used as the outbound filter for packets that originate from the peer interface.'));
		$section->add($group);

		// Peer filter list
		$group = new Form_Group('Peer Filter List ' . $peer_name);
		$group->addClass('sh_peer_' . $interface);
		$group->addClass('sh_peer_filter_list_' . $interface . '_' . $peer);
		$group->add(new Form_Input(
			'peer_filter_list_' . $interface . '_' . $peer,
			null,
			'text',
			array_get_path($peer_config, 'filter_list', ''))
		)->setHelp($filter_help_text)->setWidth(7)->setAttribute('placeholder', $filter_placeholder_text);
		$section->add($group);
	}

	$form->add($section);
}

print($form);
?>


<script type="text/javascript">
//<![CDATA[
events.push(function() {
	var available_interfaces = <?=json_encode(array_keys($available_interfaces))?>;

	// Show/hide peer filter list based on peer filter type
	function hidePeerFilterList(interface, peer) {
		let type = $('#peer_filter_type_' + interface + '_' + peer).prop('value');
		hideClass('sh_peer_filter_list_' + interface + '_' + peer, type == 'none' || type == 'deny_all');
	}

	// Show/hide peers for an interface based on enable peer filters
	function hidePeers(interface) {
		hideClass('sh_peer_' + interface, true);

		if ($('#enable_peer_filters_' + interface).prop('checked')) {
			var selected = $(".active_interfaces").val();
			var length = $(".active_interfaces :selected").length;
			for (var i = 0; i < length; i++) {
				hideClass('sh_peer_filter_type_' + interface + '_' + selected[i], false);
				hidePeerFilterList(interface, selected[i]);
			}
		}
	}

	// Show/hide interface sections base on selected interfaces
	function hideInterfaces() {
		hideClass('sh_interface', true);

		var selected = $(".active_interfaces").val();
		var length = $(".active_interfaces :selected").length;
		for (var i = 0; i < length; i++) {
			hideClass('sh_interface_' + selected[i], false);
			hidePeers(selected[i]);
		}
	}

	// Show/hide interface ip protocols based on global ip protocols
	function hideInterfaceProtocols() {
		hideClass('sh_interface_protocols', $('#global_ip_protocols').prop('value') != 'both');
	}

	// Show/hide global filter list based on global filter type
	function hideGlobalFilterList() {
		hideClass('sh_global_filter_list', $('#global_filter_type').prop('value') == 'none');
	}

	// Show/hide interface filter list based on interface filter type
	function hideInterfaceFilterList(interface, direction) {
		let type = $('#' + direction + '_filter_type_' + interface).prop('value');
		hideClass('sh_interface_' + direction + '_filter_list_' + interface, type == 'none' || type == 'deny_all');
	}


	// On changing selection for active interfaces
	$('.active_interfaces').change(function () {
		hideInterfaces();
	});

	// On changing selection for global ip protocols
	$('#global_ip_protocols').change(function() {
		hideInterfaceProtocols();
	});

	// On changing selection for global filter type
	$('#global_filter_type').change(function() {
		hideGlobalFilterList();
	});

	// On changing selection for interface filter type
	$("select[id^='inbound_filter_type_']").change(function() {
		let result = $(this).attr('id').match(/^inbound_filter_type_([\w]+)/);
		if (result && available_interfaces.includes(result[1])) {
			hideInterfaceFilterList(result[1], 'inbound');
		}
	});
	$("select[id^='outbound_filter_type_']").change(function() {
		let result = $(this).attr('id').match(/^outbound_filter_type_([\w]+)/);
		if (result && available_interfaces.includes(result[1])) {
			hideInterfaceFilterList(result[1], 'outbound');
		}
	});

	// On changing selection for enable peer filters
	$("[id^='enable_peer_filters_']").change(function() {
		let result = $(this).attr('id').match(/^enable_peer_filters_([\w]+)/);
		if (result && available_interfaces.includes(result[1])) {
			hidePeers(result[1]);
		}
	});

	// On changing selection for peer filter type
	$("select[id^='peer_filter_type_']").change(function() {
		let result = $(this).attr('id').match(/^peer_filter_type_([\w]+)_([\w]+)/);
		if (result && available_interfaces.includes(result[1])) {
			hidePeerFilterList(result[1], result[2]);
		}
	});

	// Initial page load
	hideInterfaces();
	hideInterfaceProtocols();
	hideGlobalFilterList();
	for (let interface of available_interfaces) {
		hideInterfaceFilterList(interface, 'inbound');
		hideInterfaceFilterList(interface, 'outbound');
	}

});
//]]>
</script>

<?php include("foot.inc");
