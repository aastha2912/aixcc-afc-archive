bear:
	mkdir -p debs
	wget -q -P debs http://mirrors.kernel.org/ubuntu/pool/universe/b/bear/libear_2.4.3-1_amd64.deb
	wget -q -P debs http://mirrors.kernel.org/ubuntu/pool/universe/b/bear/bear_2.4.3-1_all.deb
	dpkg-deb -x debs/libear_2.4.3-1_amd64.deb .
	dpkg-deb -x debs/bear_2.4.3-1_all.deb .
	rm -rf debs

clean:
	rm -rf usr/
