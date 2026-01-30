# BeeCD

Hive mind for your deploys. Because YOLO deploys aren't cute in production.  \
Before anything goes live, you see a diff of what's changing.

<!-- Multi-arch Docker builds fixed -->

## Getting Started

Go to [https://beecd.galleybytes.com](https://beecd.galleybytes.com) and create an account. After that, log in at your tenant URL (e.g., `https://acme.beecd.galleybytes.com`).

### Step 1: Configure Secrets

Before connecting clusters, configure your GitHub token so BeeCD can fetch manifests from your repositories.

1. Go to **Settings**
2. Under **GitHub Token**, enter your GitHub Personal Access Token (needs `repo` scope)
3. Click **Save**

### Step 2: Connect a Cluster

BeeCD deploys to existing Kubernetes clusters. Connect one by installing the BeeCD agent.

1. Go to **Clusters** -> **Add Cluster**
2. Give it a name and click **Create**
3. Click **Generate Manifest** to get the agent installation YAML
4. Apply it to your Kubernetes cluster:

```bash
kubectl apply -f agent.yaml
```

Once the agent connects, you'll see a heartbeat timestamp under **Clusters**.

### Step 3: Add a Repository

1. Go to **Repositories** -> **Add Repository**
2. Enter the GitHub repository URL (e.g., `https://github.com/your-org/manifests`)
3. Click **Save**

### Step 4: Add a Branch and Service

A **branch** tells BeeCD which git branch to watch. A **service** defines what manifests to deploy.

1. Click on your repository
2. Click **Add Branch** and enter the branch name (e.g., `main`)
3. Click **Add Service** and fill in:
   - **Name**: A lowercase identifier (e.g., `my-app`)
   - **Manifest Path Template**: Where to find manifests. Use placeholders `{cluster}`, `{namespace}`, and `{service}`.

   Examples:
   - `k8s/{cluster}/{namespace}/{service}/` - Directory per cluster/namespace/service
   - `{cluster}/{namespace}/{service}.yaml` - Single file per service

4. Click **Save**

### Step 5: Create a Cluster Group

Cluster Groups connect services to clusters. Services are assigned to groups, and clusters in that group can deploy those services.

1. Go to **Cluster Groups** -> **Add Group**
2. Name it (e.g., `production`) and click **Create**
3. Click on the group
4. Click **Add Clusters** and select your cluster
5. Click **Add Services** and select your service

### Step 6: Register a Namespace

Label a namespace in your Kubernetes cluster so BeeCD knows it can manage deployments there:

```bash
kubectl label namespace my-namespace beecd.io/enabled=true
```

The namespace will appear in Hive HQ within 60 seconds under **Clusters** -> your cluster.

### Step 7: Add Services to the Namespace

1. Go to **Clusters** -> your cluster
2. Find the namespace and click the edit icon
3. Select the services you want to deploy (only services from cluster groups this cluster belongs to will appear)
4. Click **Add**

### Step 8: Create a Version

Each release needs a git commit to deploy. Create a version:

1. Go to **Clusters** -> your cluster -> **Releases**
2. Click on a release
3. Click **Versions** -> **Add Manual Version**
4. Enter a version tag (e.g., `v1.0.0`) and the git commit SHA
5. Click **Create Version**

BeeCD will fetch the manifests from that commit.

### Step 9: Review and Approve

1. Go to **Releases**
2. Click on the pending release
3. Review the **Diff** to see what will be applied
4. Click **Approve**

The manifests will deploy to your cluster. Verify with:

```bash
kubectl get all -n my-namespace
```

## Concepts

| Term | Description |
|------|-------------|
| **Cluster** | A Kubernetes cluster connected via the BeeCD agent |
| **Cluster Group** | A collection of clusters that share the same services |
| **Service** | A deployable unit defined by a manifest path in a git repository |
| **Release** | A service deployed to a specific namespace in a cluster |
| **Version** | A git commit SHA that a release should deploy |

## Need Help?

- Submit an issue on GitHub: https://github.com/galleybytes/beecd/issues
- Verify your GitHub token has access to the repository
- Ensure the agent is running: `kubectl get pods -n beecd`
- Check agent logs: `kubectl logs -n beecd -l app=beecd-agent`

