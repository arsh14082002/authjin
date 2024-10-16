const apiConfig = {
    jwtSecret: process.env.JWT_SECRET || 'your_jwt_secret',
    emailUserName: process.env.EMAIL_USER || '',
    emailPassword: process.env.EMAIL_PASS || '',
    accountSid:
      process.env.TWILIO_ACCOUNT_SID || '', // Replace with your Account SID
    authToken:
      process.env.TWILIO_AUTH_TOKEN || '', // Replace with your Auth Token
  };
  
  export default apiConfig;
  