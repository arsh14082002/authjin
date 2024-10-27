const apiConfig = {
  mongoDB: process.env.MONGO_URI || 'mongodb://localhost:27017/<%= dbName %>',

  jwtSecret: process.env.JWT_SECRET || 'your_jwt_secret',

  emailUserName: process.env.EMAIL_USER || '',
  emailPassword: process.env.EMAIL_PASS || '',

  accountSid: process.env.TWILIO_ACCOUNT_SID || '',
  authToken: process.env.TWILIO_AUTH_TOKEN || '',

  mysqlHost: process.env.MYSQL_HOST || 'localhost',
  mysqlUser: process.env.MYSQL_USER || 'root',
  mysqlPassword: process.env.MYSQL_PASSWORD || '',
  mysqlDatabase: process.env.MYSQL_DB || 'your_database_name',
};

export default apiConfig;
