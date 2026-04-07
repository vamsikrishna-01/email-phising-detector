from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from detector.rule_factory import RuleFactory
from flask_cors import CORS
import random
import json
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Generate a secure random secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)  # Session expires after 1 hour
CORS(app, supports_credentials=True)


# Phishing quiz questions
PHISHING_QUIZ = [
    {
        'question': 'A legitimate bank will never ask for your password via email.',
        'options': ['True', 'False'],
        'answer': 'True',
        'explanation': 'Banks never ask for sensitive information like passwords via email.'
    },
    {
        'question': 'Which of these is a sign of a phishing email?',
        'options': ['Personalized greeting', 'Urgent action required', 'Company logo', 'Contact information'],
        'answer': 'Urgent action required',
        'explanation': 'Phishing emails often create a sense of urgency to pressure you into acting quickly.'
    },
    {
        'question': 'Hovering over a link in an email will show you the actual URL.',
        'options': ['True', 'False'],
        'answer': 'True',
        'explanation': 'Hovering shows the actual destination URL, which might be different from the displayed text.'
    },
    {
        'question': 'Which email address is most likely a phishing attempt?',
        'options': ['support@paypal.com', 'security@paypal.com', 'paypal@service.com', 'no-reply@paypal.com'],
        'answer': 'paypal@service.com',
        'explanation': 'Legitimate companies use their official domain names in email addresses.'
    },
    {
        'question': 'What should you do if you receive a suspicious email?',
        'options': ['Click on links to verify', 'Reply to the email', 'Forward it to your IT department', 'Download attachments to check them'],
        'answer': 'Forward it to your IT department',
        'explanation': 'Forward suspicious emails to your IT department for verification.'
    }
]

def check_email(email):
    rules = ["suspicious_links", "sender_address", "urgent_language"]
    results = {rule: False for rule in rules}
    
    # Check all rules
    for rule_type in rules:
        rule = RuleFactory.get_rule(rule_type)
        results[rule_type] = rule.check(email)
            
    return results

def get_phishing_stats():
    # In a real app, this would come from a database
    return {
        'total_emails': 1000,
        'phishing_emails': 320,
        'common_types': {
            'Suspicious Links': 45,
            'Suspicious Sender': 30,
            'Urgent Language': 25
        },
        'by_hour': [random.randint(5, 20) for _ in range(24)]
    }

@app.route('/')
def index():
    stats = get_phishing_stats()
    return render_template('index.html', stats=stats, quiz_questions=PHISHING_QUIZ[:5])  # Show first 5 questions for the quiz CTA

@app.route('/check-email', methods=['POST'])
def check_email_route():
    email = {
        'from': request.form.get('from', ''),
        'subject': request.form.get('subject', ''),
        'body': request.form.get('body', '')
    }
    results = check_email(email)
    is_phishing = any(results.values())
    return jsonify({
        'is_phishing': is_phishing,
        'details': results,
        'email': email
    })



# Quiz Routes
@app.route('/quiz')
def quiz():
    try:
        if 'quiz_questions' not in session:
            # Randomly select 10 questions for the quiz
            num_questions = min(10, len(PHISHING_QUIZ))
            quiz_questions = random.sample(PHISHING_QUIZ, num_questions)
            
            session['quiz_questions'] = quiz_questions
            session['quiz_answers'] = {}
            session['current_question'] = 0
            session['score'] = 0
            session['start_time'] = datetime.now().isoformat()
        
        current_q = session.get('current_question', 0)
        if current_q >= len(session['quiz_questions']):
            return redirect(url_for('quiz_results'))
            
        return render_template('quiz.html', 
                            question=session['quiz_questions'][current_q],
                            question_num=current_q + 1,
                            total_questions=len(session['quiz_questions']))
    except Exception as e:
        app.logger.error(f'Error in quiz route: {str(e)}')
        flash('An error occurred while loading the quiz. Please try again.', 'error')
        return redirect(url_for('index'))

@app.route('/submit-answer', methods=['POST'])
def submit_answer():
    try:
        if 'quiz_questions' not in session:
            flash('Quiz session expired. Please start a new quiz.', 'error')
            return redirect(url_for('quiz'))
            
        answer = request.form.get('answer')
        if not answer:
            flash('Please select an answer.', 'error')
            return redirect(url_for('quiz'))
            
        current_q = session.get('current_question', 0)
        session['quiz_answers'][str(current_q)] = answer
        
        # Check if answer is correct
        correct_answer = session['quiz_questions'][current_q]['answer']
        if answer == correct_answer:
            session['score'] = session.get('score', 0) + 1
        
        # Move to next question or show results
        if current_q < len(session['quiz_questions']) - 1:
            session['current_question'] = current_q + 1
        else:
            return redirect(url_for('quiz_results'))
            
        return redirect(url_for('quiz'))
    except Exception as e:
        app.logger.error(f'Error submitting answer: {str(e)}')
        flash('An error occurred. Please try again.', 'error')
        return redirect(url_for('quiz'))

@app.route('/quiz/results')
def quiz_results():
    if 'quiz_questions' not in session:
        return redirect(url_for('quiz'))
        
    try:
        # Calculate score and time taken
        score = session.get('score', 0)
        total = len(session.get('quiz_questions', []))
        time_taken = 0
        
        if 'start_time' in session:
            try:
                start_time = datetime.fromisoformat(session['start_time'])
                time_taken = (datetime.now() - start_time).total_seconds()
            except (ValueError, TypeError):
                time_taken = 0
        
        # Prepare results
        results = []
        for i, q in enumerate(session.get('quiz_questions', [])):
            user_answer = session.get('quiz_answers', {}).get(str(i), 'Not answered')
            results.append({
                'question': q['question'],
                'user_answer': user_answer,
                'correct_answer': q['answer'],
                'explanation': q['explanation'],
                'is_correct': user_answer == q['answer']
            })
        
        # Clear session
        session.pop('quiz_questions', None)
        session.pop('quiz_answers', None)
        session.pop('current_question', None)
        session.pop('start_time', None)
        
        return render_template('quiz_results.html', 
                             score=score,
                             total=total,
                             time_taken=round(time_taken, 1),
                             results=results)
    except Exception as e:
        app.logger.error(f'Error showing quiz results: {str(e)}')
        flash('An error occurred while showing results.', 'error')
        return redirect(url_for('index'))

@app.route('/stats')
def stats():
    stats = get_phishing_stats()
    return jsonify(stats)

@app.route('/detect', methods=['POST'])
def detect_phishing():
    data = request.get_json()
    email_text = {
        'from': data.get('from'),
        'subject': data.get('subject'),
        'body': data.get('body')
    }

    is_phishing = check_email(email_text)
    return jsonify({'is_phishing': is_phishing})

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
