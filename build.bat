mkdir build
rm build/*.BIN
chdir h
make clean
make
chdir ..
chdir loader
make clean
make
chdir ..
cp h/H.BIN build/H.BIN
cp loader/TN.BIN build/TN.BIN
pause