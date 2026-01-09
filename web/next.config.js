/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    serverComponentsExternalPackages: ['@anthropic-ai/sdk'],
  },
  // Increase body size limit for file uploads
  api: {
    bodyParser: {
      sizeLimit: '50mb',
    },
  },
}

module.exports = nextConfig
