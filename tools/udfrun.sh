#!/usr/bin/env bash

## UDF SSLO-Tier-Tool Helper script
## Author: Kevin Stewart (2020/12/18)
## Utility to parse a provided UDF SSH link to enable remote execution of local sslo-tier-tool commands
## UDF links are presented as "ssh://guid-url:port" and scp requires "scp -p [port] [url]:[remote-path] [local-path]"
## This script simply parses the UDF SSH link to create the correct scp syntax.

if [ "$#" -ne 3 ]
then
    echo "UDF SSLO-Tier Helper Utility"
    echo ""
    echo "  Usage:   udfrun [UDF SSH URL] sslo-tier-tool.py yaml-file"
    echo ""
    echo "  Example: udfrun ssh://9c51a294-f57a-41cb-b102-0edb9c7f4cd7.access.udf.f5.com:47000 sslo-tier-tool.py service.yml"
    echo ""
    exit
fi

## pull URL and port from UDF SSH string
url=`echo $1 |sed 's/ssh:\/\///;s/:.*//'`
port=`echo $1 |sed 's/.*.udf.f5.com://'`

tar c $2 $3 | ssh root@${url} -p ${port} "tar x -C /var/tmp/ && python /var/tmp/$2 --file /var/tmp/$3"
