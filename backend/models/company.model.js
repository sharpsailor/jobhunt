import mongoose from "mongoose";
const companySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  description: {
    type: String,
  },
  location: {
    type: String,
  },
  website: {
    type: String,
  },
  logo: {
    type: String, //url to company logo using cloudinary url
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
		ref: "User",
		required:true,
  },
},{timestamps: true});
