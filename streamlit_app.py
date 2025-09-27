import streamlit as st
from app import app as flask_app
from flask import request, jsonify

# Streamlit app
def main():
    st.title("Phishing Email Detector")
    st.write("Enter an email to check for phishing attempts")
    
    # Simple UI for email input
    email_text = st.text_area("Paste email content here:", height=200)
    
    if st.button("Check Email"):
        with st.spinner('Analyzing email...'):
            # Simulate a request to the Flask app
            with flask_app.test_request_context('/analyze', method='POST', 
                                             data={"email_content": email_text}):
                response = flask_app.full_dispatch_request()
                
            if response.status_code == 200:
                result = response.get_json()
                st.subheader("Analysis Results")
                st.json(result)
            else:
                st.error("Error analyzing email. Please try again.")

# Run the Streamlit app
if __name__ == "__main__":
    main()
