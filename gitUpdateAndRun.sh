git pull
if go build index.go ; then
	nohup sudo ./index &
else
	echo "Failed to compile"
fi
