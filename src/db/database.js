import mongoose from 'mongoose';
import 'dotenv/config'

const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017/coder69920'


export const initMongoDB = async () => {
  try {
      mongoose.set('strictQuery', false)
      await mongoose.connect(MONGO_URL);
      console.log("Conectado a la base de datos de MONGODB");
  } catch (error) {
      console.log(error);
  }
};

