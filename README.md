# Requirements
quay.io repository can be changed by setting the environment variable

`QUAY_API_ENDPOINT`

default is set as `https://quay.io/api/v1`

Please install required libraries by running
```
pip install -r requirements.txt
```

# Running the script

You can run the script by specifying a file using the --file argument
```
python secscan.py --file image_list.json
```

or

Feed data via **STDIN**
```
cat image_list.json | python secscan.py
```
