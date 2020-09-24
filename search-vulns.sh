#!/bin/bash

#Author: Fabio Defilippo
#email: 4starfds@gmail.com

if [[ "$1" == "-h" || "$1" == "--help" || "$1" == "/?" || "$1" == "?" || "$1" == "" ]];
then
  echo "search-vulns, by FabioDefilippoSoftware"
  echo "arg1=ELF file to analize"
  echo "arg2=filename of report/dump"
else
 if [[ "$1" != "" && "$2" != "" ]];
 then
  if [[ -f "$1" ]];
  then
   if [[ $(file -i "$1") == *"application"* ]];
   then
   if [[ -f "$2" ]];
   then
    echo "$2"" exists, do you want delete it?"
    read -p "Y/n (default n, exit): " RSP
    if [[ "$RSP" == "Y" ]];
    then
     rm "$2"
    else
     exit 1
    fi
   fi
    SEP="______________________________________________________________________________________________"
    FUNCTS=$(r2 -c "e scr.color=false" -c "aaaa" -c "afl" -q "$1")
    ADDS=$(echo "$FUNCTS" | awk '{print $1}')
    echo "- All Opcodes" >> "$2"
    for ADD in $ADDS; do r2 -c "e scr.color=false" -c "aaaa" -c "pdc@$ADD" -q "$1" >> "$2"; done
    EXOPS=$(grep -f asm-instructions-vulnerables.txt "$2")
    echo "$SEP" >> "$2"
    echo "- All Functions" >> "$2"
    r2 -c "e scr.color=false" -c "aaaa" -c "afll" -q "$1"  >> "$2"
    echo "$SEP" >> "$2"
    echo "- Print interesting functions" >> "$2"
    echo "$FUNCTS" | grep -f c-functions-interesting.txt >> "$2"
    echo "$SEP" >> "$2"
    echo "- Print exploitable functions" >> "$2"
    echo "$FUNCTS" | grep -f c-functions-vulnerables.txt >> "$2"
    if [[ $(sed -n '/%s/p' "$2") != "" ]];
    then
     echo -ne "\n\tprintf functions could be improved\n" >> "$2"
    fi
    echo "$SEP" >> "$2"
    echo "- Print exploitable opcodes" >> "$2"
    echo "$EXOPS" >> "$2"
    echo "$SEP" >> "$2"
   else
    echo "$1"" is not an ELF file"
   fi
  else
    echo "ERROR: ""$1"" does not exist!"
  fi
 else
  echo "ERROR: required 2 arguments"
 fi
fi
