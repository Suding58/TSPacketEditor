static class EnumerableExtensions
{
    public static IEnumerable<TSource> DistinctBy<TSource, TKey>(this IEnumerable<TSource> source, Func<TSource, TKey> keySelector)
    {
        var seen = new HashSet<TKey>();
        foreach (var element in source)
        {
            if (seen.Add(keySelector(element))) yield return element;
        }
    }
}