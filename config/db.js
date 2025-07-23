import mongoose from "mongoose";

const dbconnect = async () => {
    await mongoose.connect(process.env.MONGODB_URL)
    await console.log('Connected mongodb');
}
export default dbconnect;