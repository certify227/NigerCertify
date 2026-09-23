const configuredName = import.meta.env.VITE_APP_NAME?.trim()

export const APP_NAME = configuredName ? configuredName : 'Aureon'
export const APP_TAGLINE = 'Vos sources autorisées, sur votre écran.'
