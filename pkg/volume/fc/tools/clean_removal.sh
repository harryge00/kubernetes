#!/bin/bash

usage() {
 	echo "usage: $0 wwns lun"
	echo "	wwns    target WWNS, eg. wwn1,wwn2,wwn3,wwn4"
	echo "	lun     target lun"
}

findDisk() {
	fcRegex="pci-*:*:*.*-fc-0x$1-lun-$2"
	devPath="/dev/disk/by-path/"

	res=`ls -lh $devPath | egrep $fcRegex | awk '{print $9,$11}'`
	path=`echo $res | awk '{print $1}'`
	dev=`echo $res | awk '{print $2}' | awk -F '/' '{print $3}'`
	dm=`find /sys/block/dm-*/slaves/ -name $dev | awk 'NR==1' | awk -F '/' '{print $4}'`
}

getDeviceWWID() {
	wwid=`/lib/udev/scsi_id -g /dev/$1`
	if [[ $? -ne 0 ]]; then
		echo "Get $1 wwid failed"
		exit 1
	fi
}

flushDiskIO() {
	if [[ -b /dev/$1 ]]; then
		blockdev --flushbufs /dev/$1
	fi
}

removeDisk() {
	if [[ -b /dev/$1 ]]; then
		rm -f /dev/$1
	fi
}

removeSCSIRef() {
	if [[ -e /sys/block/$1/device/delete ]]; then
		echo 1 > /sys/block/$1/device/delete
	fi
}

removeDiskRef() {
	if [[ -h /dev/disk/by-path/$1 ]]; then
		unlink /dev/disk/by-path/$1
	fi
}

reloadMultipath() {
	multipath -W > /dev/null
}

if [[ $# -ne 2 ]]; then
	usage
	exit 1
fi

wwns=`echo $1 | sed 's/,/ /g'`
lun=$2
deviceMapper=""
declare -a devs
declare -a pathRefs

for wwn in $wwns
do
	findDisk $wwn $lun
	devs[${#devs[*]}]=$dev
	pathRefs[${#pathRefs[*]}]=$path

	if [[ $deviceMapper == "" ]];then
		deviceMapper=$dm
	elif [[ $deviceMapper != "$dm" ]];then
	    echo "Inconsistent dm: $deviceMapper $dm"
	    exit 1
	fi
done

if [[ ${#devs[@]} -eq 0 || ${#pathRefs[@]} -eq 0 ]]; then
	echo "device or symbolic link is none."
	exit 1
fi

#if [[ $deviceMapper == "" ]];then
#	getDeviceWWID ${devs[0]}
#else
#	getDeviceWWID $deviceMapper
#fi

for d in ${devs[*]}
do
	flushDiskIO $d
	removeDisk $d
	removeSCSIRef $d
done

for p in ${pathRefs[*]}
do
	removeDiskRef $p
done

reloadMultipath
