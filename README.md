# Phishing Website Classification

This project deploys a variety of Machine Learning models to accurately predict whether a URL is a phishing website.
The project makes use of a variety of techniques including blacklists as well as machine learning.

## Run the project:

The `requirements.txt` outlines the packages used in this project.

Install the required packages using `pip install -r requirements.txt`

Once these requirements are installed, the file in `data/combining-datasets.ipynb` should be run.
Next, you should navigate to the `websites/` directory and run the following commands:
`export FLASK_APP=app.py` and then `python -m flask run` which will then allow you to access the website's frontend on `127.0.0.1:5000`.
