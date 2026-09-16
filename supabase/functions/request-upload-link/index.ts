import { createClient } from 'npm:@supabase/supabase-js@2'
import { Storage } from 'npm:@google-cloud/storage'

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders })
  }

  try {
    const authHeader = req.headers.get('Authorization')
    if (!authHeader) {
        return new Response(JSON.stringify({ error: 'Missing Auth header' }), { status: 401, headers: corsHeaders })
    }

    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_ANON_KEY') ?? '',
      { global: { headers: { Authorization: authHeader } } }
    )

    const { data: { user }, error: authError } = await supabaseClient.auth.getUser()
    if (authError || !user) {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: corsHeaders })
    }

    const { fileStorageKey } = await req.json()
    if (!fileStorageKey) {
        return new Response(JSON.stringify({ error: 'fileStorageKey required' }), { status: 400, headers: corsHeaders })
    }

    // HARD SECURITY WALL: Enforce that users can only fetch links pointing to their own subfolders
    if (!fileStorageKey.startsWith(`vaults/${user.id}/`)) {
        return new Response(JSON.stringify({ error: 'Permission denied. Security signature mismatch.' }), { status: 403, headers: corsHeaders })
    }

    const storage = new Storage({
      projectId: Deno.env.get('GCP_PROJECT_ID'),
      credentials: JSON.parse(Deno.env.get('GCP_SERVICE_ACCOUNT_KEY') ?? '{}'),
    })

    const bucketName = Deno.env.get('FIREBASE_STORAGE_BUCKET') ?? ''
    const bucket = storage.bucket(bucketName)
    const file = bucket.file(fileStorageKey)

    // Generate an authorized link valid for 1 hour for internal browser memory extraction
    const [downloadUrl] = await file.getSignedUrl({
      version: 'v4',
      action: 'read',
      expires: Date.now() + 60 * 60 * 1000,
    })

    return new Response(JSON.stringify({ downloadUrl }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    })

  } catch (error: any) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' }
    })
  }
})
