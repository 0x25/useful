#!/bin/bash

# 16/03/2018
# need patator

method="GET" # POST,HEAD,OPTIONS...
follow=0 # 1 follow redirection, 0 don't follow
thread=10 # number threads
cookie=0 # 1 use cookie; 0 don't use cookie
timeout=5 # wait time
retry=1 # number of retry if fail
url="" # url+path to brute force
dict="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" # dictionnary
proxy="" # proxy ip:port
ignore="" # ignore if string in response
ignoreCode="" # 502
header="User-Agent: Googlebot-Image/1.0"
rate="" # (sec)

function helpMe()
{
        echo "Help:"
        echo -e "$0 -u URL -d file [-m <HTTP_methode> -f -t <int> -c -T <int> \
-r <int> -p <proxy:port> -I <string> -C <HttpCodeIgnore> -U <userAgent> -R <rateSec>]"
        echo "-u : target url like http://www.website.com/"
        echo "-f : active follow http redirection"
	echo "-c : active cookie"
        echo "-d : dictionnary file with folder/file to test"
        echo "-m : method HTTP to set GET (default), PUT, POST, TRACE ..."
        exit 0
}

if [ $# -eq 0 ];
then
    helpMe
    exit 1
else

while getopts ":hu:d:m:ft:cT:r:p:I:C:U:R:" option; do
case $option in
	h)
		helpMe
		exit 0
		;;
	t)
		# thread number
		thread=$OPTARG
		;;
	f)
		# follow http
		follow=1
		;;
	m)
		# method
		method=$OPTARG
		;;
	u)
		# url target
		url="${OPTARG}FILE0"
		;;
	d)
		# dictionnary path file
		dico=$OPTARG
		;;
	c)
		# accept cookie
		cookie=1
		;;
	T)
		# Timout
		timeout=$OPTARG
		;;
	r)
		# retry
		retry=$OPTARG
		;;
	p)
		# proxy:port
		proxy="'$OPTARG'"
		;;
	I)
		# string to ignore in code
		ignore=$OPTARG
		;;
	C)
		# ignore code http
		ignoreCode=$OPTARG
		;;
	U)
		# user agent
		userAgent=$OPTARG
		;;
	R)
		# rate sec
		rate=$OPTARG
		;;
	:)
		echo "$OPTARG need an argument\n see help -h"
		exit 1
		;;
esac
done
fi

if [ -z ${url} ]; then
	echo "url is not set"
	helpMe
	exit 1
fi
if [ ! -f ${dico} ]; then
	echo "dico file not found : $dico"
	helpMe
	exit 1
fi

if [ -z $proxy ]; then setProxy=""; else setProxy="http_proxy=$proxy" ;fi
if [ -z $rate ]; then setRate=""; else setRate="--rate-limite=$rate" ;fi
if [ -z $ignore ]; then setIgnore=""; else setIgnore="-x ignore:fgrep='$ignore'" ;fi
if [ -z $ignoreCode ]; then setIgnoreCode=""; else setIgnoreCode="-x ignore,retry:code='$ignoreCode'" ;fi


echo "Command Line :"
cli=$(echo "/usr/bin/patator http_fuzz method='$method' follow=$follow accept_cookie=$cookie --thread=$thread timeout=$timeout \
--max-retries=$retry url='$url' 0='$dict' header='$header' $setProxy $setIgnore $setIgnoreCode $setRate" | sed 's/ *$//')
echo $cli

eval "$cli "
