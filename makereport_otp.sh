#!/bin/sh
#set -x
#set -e


filename=$(basename "$1")
testcase="${filename%.*}"
echo -e "\e[32m>>>Running $testcase on Kryptus kNET\e[0m"
echo

mkdir -p report

python3 xml_otp_runner_multiple_batchs.py $1 $2 $3 $4

echo -e "\e[32m>>>Making report diff\e[0m"
diff -wU 100 report/expected.tex report/results.tex > report/diff.tex

sed -i "s/^-.*/\\\\textcolor{red}{&}/g; s/^+.*/\\\\textcolor{blue}{&}/g" report/diff.tex
sed -i -e "s/.\{100\}/&\n/g" report/diff.tex
sed "s/@testcase/$testcase/g" template.tex > report/report.tex

echo -e "\e[32m>>>Compiling report\e[0m"
pdflatex -output-directory report/ report/report
mv report/report.pdf $testcase.pdf

echo -e "\e[32m>>>Done!\e[0m"

