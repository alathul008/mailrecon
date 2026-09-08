from app.osint.email import analyze_email, username_candidates

def test_email_analysis():
    x=analyze_email('John.Doe+lab@GMAIL.com'); assert x['email']=='John.Doe+lab@gmail.com'; assert x['domain']=='gmail.com'; assert x['provider']=='Google'

def test_candidates():
    assert set(username_candidates('john.doe'))=={'john.doe','johndoe','john_doe','john-doe'}
