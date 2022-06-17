array=("ciscoconfparse" "dominate" "termcolor" "ipaddress" "ipaddr" "matplotlib" "numpy" "nvdlib" "pandas" "pdfkit" "requests")
for i in "${array[@]}"; do   # The quotes are necessary here
    echo "start downloading $i"
    pip install "$i"
done

