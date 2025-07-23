import  mongoose from 'mongoose';
const Schema = mongoose.Schema;
const RoleSchema = new Schema({
    roleName: {
        type: String,
        required: true,
        unique: true,
        enum: ['admin', 'user',],
        trim: true
    }
}, {
    timestamps: true
});
export default mongoose.model('Role', RoleSchema);