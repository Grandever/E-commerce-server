const userModel = require('../models/user.model')
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY)

const createCustomer = async userId => {
    try {
        const user = await userModel.findById(userId)
        if (!user) throw new Error('User not found')
        const customer = await stripe.customers.create({
            email: user.email,
            name: user.fullName,
            metadata: { userId: user._id.toString() },
        })
        await userModel.findByIdAndUpdate(userId, { customerId: customer.id })
        return customer
    } catch (error) {
        throw error
    }
}

const getCustomer = async userId => {
    try {
        const user = await userModel.findById(userId)
        if (!user) throw new Error('User not found')
        if (!user.customerId) return await createCustomer(userId)

        try {
            return await stripe.customers.retrieve(user.customerId)
        } catch (error) {
            // Recover automatically when a saved Stripe customer was removed or invalid.
            const shouldRecreate =
                error?.type === 'StripeInvalidRequestError' &&
                (error?.code === 'resource_missing' || /No such customer/i.test(error?.message || ''))

            if (!shouldRecreate) throw error

            await userModel.findByIdAndUpdate(userId, { $unset: { customerId: '' } })
            return await createCustomer(userId)
        }
    } catch (error) {
        throw error
    }
}

module.exports = { getCustomer }