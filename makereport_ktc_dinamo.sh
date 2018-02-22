#!/bin/sh
#set -x
#set -e


filename=$(basename "$1")
testcase="${filename%.*}"
echo -e "\e[32m>>>Running $testcase on Dinamo\e[0m"
echo

mkdir -p report

python3 xml_ktc_runner.py

echo -e "\e[32m>>>Making report diff\e[0m"
diff -wU 100 report/expected.tex report/results.tex > report/diff.tex

sed -i "s/^-.*/\\\\textcolor{red}{&}/g; s/^+.*/\\\\textcolor{blue}{&}/g" report/diff.tex
sed -i -e "s/.\{100\}/&\n/g" report/diff.tex
sed "s/@testcase/$testcase/g" template_dinamo.tex > report/report.tex

echo -e "\e[32m>>>Compiling report\e[0m"
pdflatex -output-directory report/ report/report
cp report/report.pdf .
mv report.pdf ktc_test_report.pdf

echo -e "\e[32m>>>Done!\e[0m"

