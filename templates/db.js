import mongoose from 'mongoose';

export const connectDB = async () => {
  try {
    mongoose.connection.on('connected', () => console.log('MongoDB connected'));
    mongoose.connection.on('error', (err) => console.log('MongoDB error: ' + err));

    await mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/mydatabase');
  } catch (error) {
    console.error('Error connecting to MongoDB:', error.message);
    process.exit(1);
  }
};
