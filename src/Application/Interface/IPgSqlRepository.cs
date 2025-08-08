using System.Data;
using Npgsql;

public interface IPgSqlRepository
{
    public Task<int> ExecuteNonQueryAsync(string sql, params NpgsqlParameter[] parameters);
    public Task<object?> ExecuteScalarAsync(string sql, params NpgsqlParameter[] parameters);
    public Task<NpgsqlDataReader> ExecuteReaderAsync(string sql, params NpgsqlParameter[] parameters);
    public Task<NpgsqlTransaction> BeginTransactionAsync();
    public Task<int> ExecuteStoredProcedureAsync(string procedureName, params NpgsqlParameter[] parameters);
    public Task BulkInsertAsync(string tableName, DataTable dataTable);
    public Task<bool> TableExistsAsync(string tableName);
}
