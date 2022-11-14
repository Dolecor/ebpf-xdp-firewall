#!/bin/bash

# Generate records for pcap_generator to generate traffic
# for example 3 from README.md

if [ -z "$1" ]; then
    echo "Specify output file"
    exit 1
fi

OUT_FILE=$1

RECORD_FMT=\
"src_mac=00:00:00:00:00:01, dst_mac=00:00:00:00:00:02, \
src_ip=%s, dst_ip=10.1.1.1, \
src_port=%s, dst_port=%s, \
ether_type=ipv4, protocol=tcp_syn"

PERMIT_IP_FMT="10.2.2.%d"
DENY_PORT_BEGIN=1024
DENY_PORT_END=1038

make_record()
{
  local src_ip=$1
  local src_port=$(printf "%d" "$(( $RANDOM % 16384 + 49152 ))");
  local dst_port=$(printf "%d" $2);

  echo "$(printf "${RECORD_FMT}" ${src_ip} ${src_port} ${dst_port})"
}


> ${OUT_FILE}


# 1) 15 packets that come from a permitted subnet 
# and have destination ports from the denied range
echo "# 1" >> ${OUT_FILE}

dst_port_iterator=${DENY_PORT_BEGIN}

for i in {1..15};
do
  src_ip=$(printf "${PERMIT_IP_FMT}" ${i});
  record="$(make_record "${src_ip}" "${dst_port_iterator}")";

  echo "${record}" >> ${OUT_FILE}

  (( dst_port_iterator++ ))
done


# 2) 15 packets that come from a permitted subnet 
# and have destination ports outside the denied range
echo "# 2" >> ${OUT_FILE}

dst_port_iterator=$(( $DENY_PORT_END + 1 ))

for i in {1..15};
do
  src_ip=$(printf "${PERMIT_IP_FMT}" ${i});
  record="$(make_record "${src_ip}" "${dst_port_iterator}")";

  echo "${record}" >> ${OUT_FILE}

  (( dst_port_iterator++ ))
done


# 3) 15 packets that do not come from a permitted subnet
# and have destination ports from the denied range
echo "# 3" >> ${OUT_FILE}

dst_port_iterator=${DENY_PORT_BEGIN}

for i in {1..15};
do
  src_ip=$(printf "123.%d.%d.%d" "$(( $RANDOM % 256 ))" "$(( $RANDOM % 256 ))" "$(( $RANDOM % 256 ))"); 
  record="$(make_record "${src_ip}" ${dst_port_iterator})";

  echo "${record}" >> ${OUT_FILE}

  (( dst_port_iterator++ ))
done


# 4) 15 packets that do not come from a permitted subnet
# and have destination ports outside the denied range
echo "# 4" >> ${OUT_FILE}

dst_port_iterator=$(( $DENY_PORT_END + 1 ))

for i in {1..15};
do
  src_ip=$(printf "123.%d.%d.%d" "$(( $RANDOM % 256 ))" "$(( $RANDOM % 256 ))" "$(( $RANDOM % 256 ))"); 
  record="$(make_record "${src_ip}" "${dst_port_iterator}")";

  echo "${record}" >> ${OUT_FILE}

  (( dst_port_iterator++ ))
done
