export const IpcChannel = {
  appGetInfo: 'app:get-info',
} as const

export type IpcChannelName = (typeof IpcChannel)[keyof typeof IpcChannel]
