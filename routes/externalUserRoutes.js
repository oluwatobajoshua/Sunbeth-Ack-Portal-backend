const express = require('express');
const multer = require('multer');
const { asyncHandler } = require('../utils/helpers');
const { adminGuard } = require('../middlewares/adminGuard');
const { makeRateLimiter } = require('../middlewares/rateLimit');
const ctrl = require('../controllers/externalUserController');

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage() });

// Search and list
router.get('/external-users/search', adminGuard, asyncHandler(ctrl.search));
router.get('/external-users', adminGuard, asyncHandler(ctrl.list));

// Onboarding invites
router.post('/external-users/invite', adminGuard, asyncHandler(ctrl.invite));
router.post('/external-users/resend', adminGuard, asyncHandler(ctrl.resend));
router.post('/external-users/invite-batch', adminGuard, express.json({ limit: '1mb' }), asyncHandler(ctrl.inviteBatch));
router.post('/external-users/resend-batch', adminGuard, express.json({ limit: '1mb' }), asyncHandler(ctrl.resendBatch));

// Password set/reset
router.post('/external-users/set-password', asyncHandler(ctrl.setPasswordHandler));
router.post('/external-users/request-reset', asyncHandler(ctrl.requestResetHandler));
router.post('/external-users/reset-password', asyncHandler(ctrl.resetPasswordHandler));

// Login and MFA
const loginLimiter = makeRateLimiter({ windowMs: 15 * 60 * 1000, max: 100 });
const mfaLimiter = makeRateLimiter({ windowMs: 5 * 60 * 1000, max: 100 });
router.post('/external-users/login', loginLimiter, asyncHandler(ctrl.loginHandler));
router.post('/external-users/mfa/setup', mfaLimiter, asyncHandler(ctrl.mfaSetupHandler));
router.post('/external-users/mfa/verify', mfaLimiter, asyncHandler(ctrl.mfaVerifyHandler));
router.post('/external-users/mfa/disable', mfaLimiter, asyncHandler(ctrl.mfaDisableHandler));

// Admin updates
router.patch('/external-users/:id', adminGuard, express.json({ limit: '1mb' }), asyncHandler(ctrl.patchUser));
router.delete('/external-users/:id', adminGuard, asyncHandler(ctrl.deleteUser));

// Bulk upload
router.post('/external-users/bulk-upload', adminGuard, upload.single('file'), asyncHandler(ctrl.bulkUpload));

module.exports = router;
