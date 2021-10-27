
#
# (c) 2021/09/30 - raymond@burkholder.net
# interface/mac scanner for looking at a list of devices, pulling config & mac info,
#  and matching against a supplied list of mac addresses to obtain device/port assignments

# requires following snnpwalker app to pull snmp info
#   provides .csv output
# https://ezfive.com/snmpsoft-tools/snmp-walk/

# an snmp oid lookup tool
# https://cric.grenoble.cnrs.fr/Administrateurs/Outils/MIBS/?oid=1.3.6.1.2.1.2.2.1

# used snmpv2 'public' as community string

# this file was designed to find vlan 801 on interfaces

$oid_mac   = '.1.3.6.1.2.1.17.7.1.2.2.1.1'
$oid_port  = '.1.3.6.1.2.1.17.7.1.2.2.1.2'
$oid_vlan  = '.1.3.6.1.2.1.17.7.1.4.5.1.1'
$oid_alias = '.1.3.6.1.2.1.31.1.1.1.18'
$oid_name  = '.1.3.6.1.2.1.2.2.1.2' # ethx
$oid_mtu   = '.1.3.6.1.2.1.2.2.1.4'
$oid_speed = '.1.3.6.1.2.1.2.2.1.5' # bits per second
$oid_admin = '.1.3.6.1.2.1.2.2.1.7' # 1 up, 2 dn
$oid_oper  = '.1.3.6.1.2.1.2.2.1.8' # 1 up, 2 dn
$oid_last  = '.1.3.6.1.2.1.2.2.1.9'

$start = get-date

$listDevice = import-csv -path .\device.csv -Delimiter ',' -Header 'status','name','addr','mac'
$macDevice = @()
foreach ( $row in $listDevice ) {
  $macDevice += $row.mac
}
#write-host "$($macDevice)"

$listOnt = import-csv -path .\to_walk.csv -Delimiter ',' -Header 'host','addr'

$mac_table = @{} # key(sequence), values(mac,port)
$if_table = @{}  # key(sequence), values(<if stuff>)
$mac_map  = @{}  # key(mac), value(port)

$mac_lu_export = @()
$vlan801_macs = @()

$walk = $True

foreach ( $line in $listOnt ) {

  $mac_table.Clear()
  $if_table.Clear()
  $mac_map.Clear()

  write-host "=========="

  write-host "Testing $($line.host) is $($line.addr)"

  if (Test-Connection $line.addr -count 1 -ea 0) {

    $name = $line.host + '.csv'
    
    # interface basics
    if ( $walk ) {
      .\SnmpWalk.exe -r:$line.addr -c:public -os:.1.3.6.1.2.1.2.2.1.2 -op:.1.3.6.1.2.1.2.2.1.10.0 -csv > $name
    }

    $listValues = import-csv -path $name -Delimiter ',' -Header 'oid','type','value'
    foreach ( $row in $listValues ) {

      #write-host "$($row.oid)|$($row.value)"
      $digits = $row.oid.Split( '.' )
      $base = ( $digits[ 0..($digits.Count-2)] -join "." )

      [int]$sequence = $digits[ $digits.Count - 1 ]
      if ( $if_table.ContainsKey( $sequence ) ) {}
      else {
        $if_table[ $sequence ] = @{}
      }

      if ( $oid_name -eq $base ) {
        $if_table[ $sequence ].Add( 'seen', @() )
      }

      if ( $oid_mtu -eq $base ) {
        $mtu = $row.value
        $if_table[ $sequence ].Add( 'mtu', $mtu )
      }

      if ( $oid_speed -eq $base ) {
        $speed = $row.value
        $if_table[ $sequence ].Add( 'speed', $speed / 1000000 )
      }

      if ( $oid_admin -eq $base ) {
        [int]$value = $row.value
        $admin = '--'
        if ( 1 -eq $value ) { $admin = 'up' }
        if ( 2 -eq $value ) { $admin = 'dn' }
        $if_table[ $sequence ].Add( 'admin', $admin )
      }

      if ( $oid_oper -eq $base ) {
        [int]$value = $row.value
        $oper = '--'
        if ( 1 -eq $value ) { $oper = 'up' }
        if ( 2 -eq $value ) { $oper = 'dn' }
        $if_table[ $sequence ].Add( 'oper', $oper )
      }

      if ( $oid_last -eq $base ) {
        $last = $row.value
        $if_table[ $sequence ].Add( 'last', $last )
      }
    }

    # interface alias
    if ( $walk ) {
      .\SnmpWalk.exe -r:$line.addr -c:public -os:.1.3.6.1.2.1.31.1.1.1.18 -op:.1.3.6.1.2.1.31.1.1.1.19 -csv > $name
    }

    $listValues = import-csv -path $name -Delimiter ',' -Header 'oid','type','value'
    foreach ( $row in $listValues ) {

      #write-host "$($row.oid)|$($row.value)"
      $digits = $row.oid.Split( '.' )
      $base = ( $digits[ 0..($digits.Count-2)] -join "." )

      [int]$sequence = $digits[ $digits.Count - 1 ]
      if ( $if_table.ContainsKey( $sequence ) ) {}
      else {
        $if_table[ $sequence ] = @{}
      }

      if ( $oid_alias -eq $base ) {
        $alias = $row.value
        $if_table[ $sequence ].Add( 'alias', $alias )
      }
    }

    # vlan
    if ( $walk ) {
      .\SnmpWalk.exe -r:$line.addr -c:public -os:.1.3.6.1.2.1.17.7.1.4.5.1.1 -op:.1.3.6.1.2.1.17.7.1.4.5.1.2.0 -csv > $name
    }

    $listValues = import-csv -path $name -Delimiter ',' -Header 'oid','type','value'
    foreach ( $row in $listValues ) {

      #write-host "$($row.oid)|$($row.value)"
      $digits = $row.oid.Split( '.' )
      $base = ( $digits[ 0..($digits.Count-2)] -join "." )

      [int]$sequence = $digits[ $digits.Count - 1 ]
      if ( $if_table.ContainsKey( $sequence ) ) {}
      else {
        $if_table[ $sequence ] = @{}
      }

      if ( $oid_vlan -eq $base ) {
        $vlan = $row.value
        $if_table[ $sequence ].Add( 'vlan', $vlan )
      }
    }

    # mac, port #
    if ( $walk ) {
      .\SnmpWalk.exe -r:$line.addr -c:public -os:.1.3.6.1.2.1.17.7 -op:.1.3.6.1.2.1.17.7.1.2.2.1.3.0 -csv > $name
    }

    $listValues = import-csv -path $name -Delimiter ',' -Header 'oid','type','value'
    foreach ( $row in $listValues ) {
      #write-host "$($row.oid)|$($row.value)"
      $digits = $row.oid.Split( '.' )
      $base = ( $digits[ 0..($digits.Count-2)] -join "." )

      [int]$sequence = $digits[ $digits.Count - 1 ]
      if ( $mac_table.ContainsKey( $sequence ) ) {}
      else {
        $mac_table[ $sequence ] = @{}
      }

      if ( $oid_mac -eq $base ) {
        $raw_mac = $row.value.TrimEnd()
        $octets = $raw_mac.Split( ' ' )
        $mac = $octets -join ':'
        $mac_table[ $sequence ].Add( 'mac', $mac )
        #write-host " mac: $($mac)"
      }

      if ( $oid_port -eq $base ) {
        [int]$port = $row.value
        $mac_table[ $sequence ].Add( 'port', $port )
        #write-host " port: $($port)"
      }
    }

    foreach ( $key in $mac_table.Keys ) {
      $mac = $mac_table[ $key ].mac
      $port = $mac_table[ $key ].port
      #write-host " seen $($port),$($mac)"
      if ( 0 -lt $port ) {
        $if_table[ $port ].seen += $mac
      }

      $mac_map[ $mac ] = $port
    }

    # ----

    foreach ( $key in ( $if_table.Keys | sort ) ) {
      $row = $if_table[ $key ]
      #write-host "port $($key): $($row.alias),$($row.vlan),$($row.admin),$($row.oper),$($row.last),$($row.speed),$($row.mtu)"
      write-host "$($row.alias),$($row.vlan),$($row.admin),$($row.oper),$($row.speed),$($row.mtu),$($row.last),$($row.seen)"
    }

    foreach ( $mac in $macDevice ) {
      if ( $mac_map.ContainsKey( $mac ) ) {
        $port = $mac_map[ $mac ]
        if ( 1 -eq $port ) {} # skip the uplink port, which is not local device port
        else {
          $if_alias = $if_table[ $port ].alias
          $mac_lu_export += New-Object PsObject -property @{
            'mac' = $mac
            'host' = $line.host
            'alias' = $if_alias
          }
          #write-host "$($mac),$($line.host),$($if_alias)"
        }
      }
    }

    foreach ( $mac in $mac_map.Keys ) {
      $port = $mac_map[ $mac ]
      if ( 1 -eq $port ) {} # ignore the uplink port
      else {
        if ( '801' -eq $if_table[ $port ].vlan ) {
          $vlan801_macs += New-Object PsObject -property @{
            'mac' = $mac
            'host' = $line.host
            'alias' = $if_alias
          }
        }
      }
    }
  }
} # for each ont

$export_name = ".\mac_locations.csv"
$mac_lu_export | export-csv -notype $export_name
start $export_name

$export_name = ".\vlan801_macs.csv"
$vlan801_macs | export-csv -notype $export_name
start $export_name

$end = get-date

write-host "======="
write-host "duration: $($start) - $($end)"
