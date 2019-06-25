#!/bin/bash
MAVEN_REPOSITORY_PATH=${MAVEN_REPOSITORY_PATH:-"~/.m2/repository"}

TBOOT_VERSION="1.9.7"
TBOOT="tboot-${TBOOT_VERSION}"
TBOOT_URL="http://downloads.sourceforge.net/project/tboot/tboot/${TBOOT}.tar.gz"

yum_detect() {
  yum=`which yum 2>/dev/null`
  if [ -n "$yum" ]; then return 0; else return 1; fi
}

aptget_detect() {
  aptget=`which apt-get 2>/dev/null`
  aptcache=`which apt-cache 2>/dev/null`
  if [ -n "$aptget" ]; then return 0; else return 1; fi
}

download_prerequisites() {
  # RHEL
  if yum_detect; then
    sudo -n yum install -y wget
    if [ $? -ne 0 ]; then echo "Failed to install prerequisites through package installer"; return 1; fi
    return
  # UBUNTU
  elif aptget_detect; then
    sudo -n apt-get install -y wget
    if [ $? -ne 0 ]; then echo "Failed to install prerequisites through package installer"; return 1; fi
    return
  fi
  return 2
}

maven_install() {
  local file_name="${1}"
  local group_id="${2}"
  local artifact_id="${3}"
  local version="${4}"
  local packaging="${5}"
  local classifier="${6}"
  mvn install:install-file -Dfile="${file_name}" -DgroupId="${group_id}" -DartifactId="${artifact_id}" -Dversion="${version}" -Dpackaging="${packaging}" -Dclassifier="${classifier}"
}

download_tboot() {
  if [ ! -f "${TBOOT}.tar.gz" ]; then
    wget --no-check-certificate "${TBOOT_URL}"
  fi
}
maven_install_tboot() {
  maven_install "${TBOOT}.tar.gz" "net.sourceforge.tboot" "tboot" "${TBOOT_VERSION}" "tgz" "sources"
}
download_and_maven_install_tboot() {
  if [ ! -f "${MAVEN_REPOSITORY_PATH}/net/sourceforge/tboot/tboot/${TBOOT_VERSION}/${TBOOT}*.tgz" ]; then
    download_tboot
    maven_install_tboot
  fi
}


echo "Downloading and installing prerequisites..."
download_prerequisites
if [ $? -ne 0 ]; then echo "Failed to install prerequisites through package manager"; exit 1; fi
echo "Downloading and maven installing tboot..."
download_and_maven_install_tboot
if [ $? -ne 0 ]; then echo "Failed to download and maven install tboot"; exit 6; fi
