const checkAdminRole = async (req, res, next) => {
    try {
        // Kiểm tra xem user có tồn tại không
        if (!req.user) {
            throw new Error('Không tìm thấy thông tin người dùng', 401);
        }

        // Kiểm tra role của user
        if (req.user.role !== 'admin') {
            return res.status(403).json({ message: 'Bạn không có quyền truy cập chức năng này' });
        }

        next();
    } catch (error) {
        next(error);
    }
};

export default checkAdminRole; 