#!/bin/bash -e
#edit .properties config file
prop_replace () {
  target_file=${3}
  echo 'replacing target file ' ${target_file}
  sed -i -e "s|$1\s\?=\s\?.*$|$1=$2|" ${target_file}
}

prop_uncomment() {
	target_file=${2}
	echo "Uncommenting ${target_file}"
	sed -i -e "s|^\#$1|$1|" ${target_file}
}

#edit .xml config file
xml_uncomment() {
  target_file=${2}
  echo "Uncommenting ${target_file}"
  sed -i -e "s|<!--$1>|<$1>|" ${target_file}
  sed -i -e "s|</$1-->|</$1>|" ${target_file}
}

xml_replace() {
  property_name=$1
  property_value=$2
  property_xpath=$3
  target_file=$4

  if [ -n "${property_value}" ]; then
    xmlstarlet ed -L -O -u "${property_xpath}/${property_name}" -v ${property_value} "${target_file}"
    #echo "${property_xpath}/${property_name} -v '${property_value}' ${target_file}"
  fi
}

xml_add() {
  property_name=$1
  property_value=$2
  property_xpath=$3
  target_file=$4
  xmlstarlet -q sel -t -m "${property_xpath}" -v "${property_name}" "${target_file}"
  if [ $? -gt 0 ]; then
    xmlstarlet ed -L -O -s "${property_xpath}" -t 'elem' -n "${property_name}" -v "${property_value}" "${target_file}"
  else
    xmlstarlet ed -L -O -u "${property_xpath}/${property_name}" -v "${property_value}" "${target_file}"
  fi
}

xml_append_elem() {
    property_name=$1
    property_value=$2
    property_xpath=$3
    target_file=$4
    pos=1
    first_attr=$5
    [[ ${property_xpath} =~ ^(.*)(/${property_name}.*) ]]
    parent_xpath=${BASH_REMATCH[1]}
    [[ ${first_attr} =~ ^(.*)=(.*) ]]
    first_attr_name=${BASH_REMATCH[1]}
    first_attr_value=${BASH_REMATCH[2]}
    xmlstarlet -q sel -t -m "${parent_xpath}" -v "${property_name}"'[@'$first_attr_name'="'$first_attr_value'"]' "${target_file}"
    #echo "DEBUG: ${parent_xpath}" -v "${property_name}"'[@'$first_attr_name'="'$first_attr_value'"]' "${target_file}"
    if [ $? -gt 0 ]; then
      xmlstarlet ed -L -O -a "${property_xpath}" -t 'elem' -n "${property_name}" -v "${property_value}" "${target_file}"
      for i in "${@:5}"; do
        [[ $i =~ ^(.*)=(.*) ]]
        attr_name=${BASH_REMATCH[1]}
        #echo "DEBUG $attr_name"
        attr_value=${BASH_REMATCH[2]}
        #echo "DEBUG $attr_value"
        if  [[ ${pos} -eq 1 ]]; then
          xmlstarlet ed -L -O -i "${parent_xpath}/${property_name}[not(@${attr_name})]" -t "attr" -n "${attr_name}" -v "${attr_value}" "${target_file}"
          #echo "${parent_xpath}/${property_name}[not(@${attr_name})]"
        else
          xmlstarlet ed -L -O -i "${parent_xpath}/${property_name}[@${old_attr_name}=\"${old_attr_value}\"]" -t "attr" -n "${attr_name}" -v "${attr_value}" "${target_file}"
          #echo "${parent_xpath}/${property_name}[@${old_attr_name}=\"${old_attr_value}\"]"
        fi
        old_attr_name=${attr_name}
        old_attr_value=${attr_value}
        ((pos+=1))
        #echo "DEBUG $pos"
      done
    else
      xmlstarlet ed -L -O -u "${parent_xpath}/${property_name}"'[@'${first_attr_name}'="'${first_attr_value}'"]' -v "${property_value}" "${target_file}"
      #echo "${parent_xpath}/${property_name}"'[@'${first_attr_name}'="'${first_attr_value}'"]'
    fi
}

xml_append_attr() {
  property_name=$1
  property_value=$2
  property_xpath=$3
  target_file=$4
  [[ ${property_value} =~ ^(.*)=(.*) ]]
  attr_name=${BASH_REMATCH[1]}
  attr_value=${BASH_REMATCH[2]}
  xmlstarlet ed -L -O -i "${property_xpath}/${property_name}" -t "attr" -n "${attr_name}" -v "${attr_value}" "${target_file}"
}

xml_delete() {
  property_name=$1
  property_value=$2
  property_xpath=$3
  target_file=$4
  xmlstarlet ed -L -O -d "${property_xpath}[${property_name}[contains(text(), '${property_value}')]]" "${target_file}"
  #echo "${property_xpath}[${property_name}[contains(text(), '${property_value}')]]" "${target_file}"
  #xmlstarlet ed -L -O -d "//_:Server/_:OAuth/_:SupportedGrantTypes/_:SupportedGrantType[_:GrantTypeName[contains(text(), 'urn:ietf:params:oauth:grant-type:saml2-bearer')]]" "${target_file}"
}

#edit .json config file
json_replace() {
  property_name=$1
  property_value=$2
  property_xpath=$3
  target_file=$4
  jq "${property_xpath}.${property_name} = \"${property_value}\"" "${target_file}"|sponge "${target_file}"
}

json_add() {
  property_name=$1
  property_value=$2
  property_xpath=$3
  target_file=$4
  jq "${property_xpath}.${property_name} += [\"${property_value}\"]" "${target_file}"|sponge "${target_file}"
}

yml_replace() {
  property_name=$1
  property_value=$2
  property_xpath=$3
  target_file=$4
  yq w -i ${target_file} "${property_xpath}.${property_name}" ${property_value}
}

yml_add() {
  property_value=$1
  property_xpath=$2
  target_file=$3
  yq w -i ${target_file} ${property_xpath} ${property_value}
}
