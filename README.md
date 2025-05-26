# CBC Health Analyzer App
The CBC Health Analyzer App is a web-based application designed to analyze Complete Blood Count (CBC) data. 

## Features 
### CBC Data Analysis: Upload and analyze CBC data from CSV files.
### Interactive Visualizations: Generate charts and graphs to visualize blood count metrics.
### User-Friendly Interface: Navigate through an intuitive web interface built with HTML and CSS.
### Data Storage: Store and retrieve analysis results using a SQLite database.

## Technologies Used
### Backend: Python (Flask)
### Frontend: HTML, CSS
### Database: SQLite
### Data Handling: CSV files

## Installation
### 1. Clone the repository: 
```git clone https://github.com/haroldevvv/CBC-Health-Analyzer-App.git```
```cd CBC-Health-Analyzer-App```
### 2. Create a virtual environment: 
```python3 -m venv venv```
```source venv/bin/activate  # On Windows: venv\Scripts\activate``` 
### 3. Install dependencies: ```pip install -r requirements.txt```
### 4. Run the application: ```python app.py```
### 5. Access the app: Open your web browser and navigate to ```http://127.0.0.1:5000/```.

## Project Structure
<pre><code>```plaintext CBC-Health-Analyzer-App/ ├── app.py # Main Flask application ├── cbcdata.csv # Sample CBC data ├── hrcbc_app.db # SQLite database ├── static/ # Static files (CSS, JS, images) ├── templates/ # HTML templates └── requirements.txt # Python dependencies ```</code></pre>

## License
### This project is licensed under the MIT License.

## Acknowledgements
### Developed by haroldevvv. 
