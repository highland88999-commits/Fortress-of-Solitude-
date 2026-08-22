import { createClient } from 'npm:@supabase/supabase-js@2'
import { Storage } from 'npm:@google-cloud/storage'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

Deno.serve(async (req) => {
  // Handle CORS for preflight requests
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
        return new Response(JSON.stringify({ error: 'Missing Auth header' }), { status: 401, headers: corsHeaders })
    }

    // Initialize Supabase Client with the user's auth context
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: authHeader } } }
    )

    // Verify JWT and get the authenticated user
    const { data: { user }, error: authError } = await supabaseClient.auth.getUser()
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: corsHeaders })
    }

    const { filename } = await req.json()
    if (!filename || !filename.endsWith('.zip')) {
        return new Response(JSON.stringify({ error: 'Valid .zip filename required' }), { status: 400, headers: corsHeaders })
    }

    // Initialize Google Cloud Storage with Service Account
    const storage = new Storage({
      projectId: Deno.env.get('GCP_PROJECT_ID'),
      credentials: JSON.parse(Deno.env.get('GCP_SERVICE_ACCOUNT_KEY') ?? '{}'),
    })

    const bucketName = Deno.env.get('FIREBASE_STORAGE_BUCKET') ?? ''
    const bucket = storage.bucket(bucketName)
    
    // Structure path to ensure tenant isolation by user ID
    const file = bucket.file(`uploads/${user.id}/${filename}`)

    // Generate a V4 signed URL for write access 
    const [url] = await file.getSignedUrl({
      version: 'v4',
      action: 'write',
      expires: Date.now() + 15 * 60 * 1000, // 15 minutes
      contentType: 'application/zip',
    })

    return new Response(JSON.stringify({ url, path: file.name }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
  }
})
