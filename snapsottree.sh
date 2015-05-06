#!/bin/sh
dota=~/Steam/steamapps/common/"dota 2 beta"
out="./out"
steamcmd=~/steamcmd/steamcmd.sh
log=updates.log

echo "starting dota2 update at $(date -Iseconds -u)" >> "${log}"

steamargs="+@ShutdownOnFailedCommand 1 \
          +@sSteamCmdForcePlatformType windows \
          +login anonymous \
          +app_update 570 \
          +quit"

if "${steamcmd}" $steamargs > steamcmd.log; then
  echo "updated dota successfully" >> "${log}"
  if cmp "${dota}/dota/steam.inf" "${out}/steam.inf"; then
    echo "no updates for dota" >> "${log}"
    exit 0
  fi
else
  exit 1
fi

if [ -z "${out}" ] || [ "${out}" = "/" ]; then
  echo "COWARDLY REFUSING TO PUT UPDATE INFO TO ROOT" >&2
  exit -666
fi

rm -rf -- "${out}"/*
[ -d "${out}" ] || mkdir "${out}"

cp "${dota}/dota/steam.inf" -t "${out}/"
mkdir "${out}/resource"
cp "${dota}/dota/resource/items_english.txt" "${dota}/dota/resource/dota_english.txt" -t "${out}/resource/"

./checksums.py "${dota}/dota/" > "${out}/dir.sha.txt"
for i in pak01 scaleform_cache sound_vo_english; do
   ./vpk.py "${dota}/dota/${i}_dir.vpk" -c > "${out}/${i}.sha.txt"
done

./vpk.py "${dota}/dota/pak01_dir.vpk" -x $(cat ./to-extract.txt) -d "${out}"


cd "${out}"
git checkout readme.md
git add .
git add -u .
if git diff-index --quiet HEAD --; then
  echo "no changes for dota 2 found" >> "${log}"
else
  git commit -am "automatic update, $(grep ClientVersion steam.inf | head -1)"
  git push -u origin master
fi
