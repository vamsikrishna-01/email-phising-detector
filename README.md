# Phishing Email Detector

A web application that helps detect phishing attempts in emails. The application analyzes email content for common phishing indicators and provides a risk assessment.

## Features

- Email content analysis for phishing indicators
- Interactive quiz to test phishing awareness
- Modern, responsive user interface
- Real-time detection results

## Setup and Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/saiprudhvi01/Phising-email-detector.git
   cd Phising-email-detector
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the application locally:
   ```bash
   python app.py
   ```

4. Open your browser and navigate to `http://localhost:5000`

## Deployment

### Streamlit Cloud

This application is configured for deployment on Streamlit Cloud:

1. Fork this repository
2. Go to [Streamlit Cloud](https://share.streamlit.io/)
3. Click "New app" and select your forked repository
4. Set the main file path to `streamlit_app.py`
5. Click "Deploy!"

## Project Structure

- `app.py` - Main Flask application
- `streamlit_app.py` - Streamlit wrapper for deployment
- `templates/` - HTML templates for the web interface
- `static/` - CSS and JavaScript files
- `detector/` - Phishing detection modules
- `config/` - Configuration files

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
