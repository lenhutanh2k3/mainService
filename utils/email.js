import nodemailer from 'nodemailer';

export async function sendEmail(to, subject, text, html = null) {
    const EMAIL_USER = process.env.EMAIL_USER;
    const EMAIL_PASS = process.env.EMAIL_PASS;
    if (!EMAIL_USER || !EMAIL_PASS) {
        console.error('Email credentials not configured');
        return false;
    }
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: { user: EMAIL_USER, pass: EMAIL_PASS },
    });

    try {
        console.log('[SEND EMAIL] Sending email with:');
        console.log('To:', to);
        console.log('Subject:', subject);
        console.log('Text:', text);
        console.log('HTML:', html ? '[HTML content present]' : '[No HTML]');
        const result = await transporter.sendMail({ from: EMAIL_USER, to, subject, text, html });
        console.log('[SEND EMAIL] Nodemailer result:', result);
        return true;
    } catch (error) {
        console.error('Lỗi gửi email:', error);
        return false;
    }
} 