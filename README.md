quay.io repository can be changed by setting the environment variable

`QUAY_API_ENDPOINT`

Please install required libraries by running
`
pip install -r requirements.txt
`

You can run the script by specifying a file using the --file argument
`
python script.py --file image_list.json
`

or

feed data via STDIN
`
cat image_list.json | python script.py
`
