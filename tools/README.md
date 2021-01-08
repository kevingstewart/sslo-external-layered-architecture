## UDFRUN Tool ##

Useful in an internal F5 environment to push sslo-tier-toool configurations to a BIG-IP in UDF. To use, copy the SSH URL of the respective UDF BIG-IP LTM instance.

Chmod this Bash script to make it executable:

`chmod +x udfrun.sh`

Use the following syntax:

./udfrun.sh [SSH URL] sslo-tier-tool.py config-file.yml

Example:

`./udfrun.sh ssh://1234567-f1f1-abab-xyxy-1234567890ac.access.udf.f5.com:47007 sslo-tier-tool.py layer3service.yml`
